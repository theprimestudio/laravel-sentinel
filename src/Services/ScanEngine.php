<?php

namespace ThePrimeStudio\LaravelSentinel\Services;

use ThePrimeStudio\LaravelSentinel\Models\FileInventory;
use ThePrimeStudio\LaravelSentinel\Models\Finding;
use ThePrimeStudio\LaravelSentinel\Models\FindingEvent;
use ThePrimeStudio\LaravelSentinel\Models\ScanRun;
use Illuminate\Contracts\Cache\Lock;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use RuntimeException;

/**
 * File-system scanner: inventory + SHA-256 baseline, heuristic analysis, optional ClamAV.
 *
 * Guarantees:
 *  - single active scan per host/cache store (atomic lock);
 *  - suspicious content is only read as bytes, never included/executed;
 *  - symlinks are never followed; links pointing outside the project are reported;
 *  - a run with errors, gaps in engine coverage or an exception is never "completed/clean";
 *  - progress is checkpointed and resumable in deterministic walk order.
 */
use ThePrimeStudio\LaravelSentinel\Contracts\ScannerInterface;

class ScanEngine implements ScannerInterface
{
    protected string $base;

    protected ScanRun $run;

    protected bool $dryRun = false;

    /** @var array<string, array{id: int, sha256: ?string, baseline_sha256: ?string, size: int, mtime: int, scanned: bool, missing: bool}> */
    protected array $inventory = [];

    protected bool $baselineExists = false;

    /** @var array<string, true> */
    protected array $seen = [];

    /** @var list<string> */
    protected array $clamQueue = [];

    /** @var list<string> */
    protected array $gaps = [];

    /** @var array<string, true> */
    protected array $quarantinedNow = [];

    /** @var list<int> */
    protected array $pendingTouches = [];

    /** @var list<array{path: string, severity: string, rule: string, confidence: int}> */
    protected array $reported = [];

    /** @var callable(string): void|null */
    protected $output = null;

    protected float $startedAt = 0;

    protected int $processed = 0;

    protected int $oversized = 0;

    public function __construct(
        protected HeuristicAnalyzer $analyzer,
        protected ClamAvScanner $clamav,
        protected QuarantineService $quarantine,
    ) {
        $this->base = rtrim(str_replace('\\', '/', base_path()), '/');
    }

    /**
     * @param  array{mode?: string, paths?: list<string>, dry_run?: bool, resume?: bool, max_files?: ?int, output?: callable, lock_wait?: int}  $options
     */
    public function run(array $options = []): ScanRun
    {
        $mode = $options['mode'] ?? 'incremental';
        if (! in_array($mode, ['full', 'incremental', 'path'], true)) {
            throw new RuntimeException("Unknown scan mode [{$mode}]");
        }

        // A stale `config:cache` from before this feature leaves the whole section missing; scanning
        // would silently cover nothing. Refuse instead of producing an empty "completed" run.
        if (! is_array(config('security.scanner')) || empty(config('security.scanner.roots'))) {
            throw new RuntimeException('Scanner configuration not loaded (security.scanner.roots is empty). '
                .'If config is cached, run: php artisan config:clear (or config:cache) after deploying config/security.php.');
        }

        $this->dryRun = (bool) ($options['dry_run'] ?? false);
        $this->output = $options['output'] ?? null;
        $this->startedAt = microtime(true);
        $this->resetState();

        $lock = Cache::lock('security:scan', (int) config('security.scanner.lock_seconds', 3600));
        $acquired = ($options['lock_wait'] ?? 0) > 0 ? $lock->block((int) $options['lock_wait']) : $lock->get();
        if (! $acquired) {
            throw new ScanLockedException('Another security scan is already running.');
        }

        try {
            return $this->execute($mode, $options);
        } finally {
            $lock instanceof Lock && $lock->release();
        }
    }

    protected function execute(string $mode, array $options): ScanRun
    {
        $this->failStaleRuns();

        $resumeFrom = ! empty($options['resume']) ? $this->resumableRun($mode) : null;
        [$targets, $roots] = $this->resolveTargets($mode, $options['paths'] ?? []);

        $this->run = new ScanRun([
            'mode' => $mode,
            'status' => 'running',
            'dry_run' => $this->dryRun,
            'started_at' => now(),
            'roots' => $roots,
            'host' => gethostname() ?: null,
            'pid' => getmypid() ?: null,
            'resumed_from_id' => $resumeFrom?->id,
            'engines' => [],
        ]);
        $this->persist($this->run);

        try {
            $this->loadInventory();
            $clamStatus = $this->clamav->status();
            $engines = ['heuristic' => 'active', 'sha256_inventory' => 'active', 'clamav' => $clamStatus['available'] ? $clamStatus['engine'] : 'unavailable'];
            if (! $clamStatus['available']) {
                $this->gaps[] = 'ClamAV: '.$clamStatus['reason'].' Signature-based malware detection did NOT run.';
            }
            if (! $this->baselineExists) {
                $this->gaps[] = 'No prior baseline: this run establishes it; integrity changes before now cannot be detected.';
            }
            $this->run->engines = $engines;

            $skipUntil = $resumeFrom?->checkpoint;
            $maxFiles = $options['max_files'] ?? null;
            $truncated = false;

            foreach ($targets as $target) {
                foreach ($this->walk($target) as $file) {
                    $key = self::orderKey($file['rel']);
                    if ($skipUntil !== null && strcmp($key, $skipUntil) <= 0) {
                        $this->seen[$file['rel']] = true;

                        continue;
                    }

                    $this->processFile($file, $mode);
                    $this->processed++;
                    $this->run->checkpoint = $key;

                    if ($this->processed % (int) config('security.scanner.checkpoint_every', 200) === 0) {
                        $this->flushClamQueue();
                        $this->persist($this->run);
                    }
                    if ($this->processed % (int) config('security.scanner.throttle_every', 500) === 0) {
                        usleep((int) config('security.scanner.throttle_microseconds', 20000));
                    }
                    if (($maxFiles && $this->processed >= $maxFiles) || $this->overTimeBudget()) {
                        $truncated = true;
                        break 2;
                    }
                }
            }

            $this->flushClamQueue();

            if ($mode === 'path') {
                $this->detectDeletedExplicit($options['paths'] ?? []);
            } elseif (! $truncated && $resumeFrom === null) {
                $this->detectDeleted($roots);
            } elseif ($resumeFrom !== null && ! $truncated) {
                $this->gaps[] = 'Resumed run: deletion detection skipped (requires an uninterrupted pass).';
            }

            if ($this->oversized > 0) {
                $this->gaps[] = "{$this->oversized} file(s) exceeded max_file_bytes: hashed".($this->clamav->isAvailable() ? ' and ClamAV-scanned' : '').' but not content-analysed.';
            }

            $status = $truncated ? 'partial' : ($this->run->errors_count > 0 ? 'partial' : 'completed');

            // Covering zero files is never a clean result (missing roots, permissions, wrong base path).
            if ($mode !== 'path' && $this->run->files_seen === 0 && $resumeFrom === null) {
                $this->run->error = 'No files were found to scan. Check that the configured roots exist and are readable by this user: '
                    .implode(', ', (array) config('security.scanner.roots'));
                $status = 'failed';
            }
            if ($truncated) {
                $this->gaps[] = 'Run stopped early (time budget or --max-files); resume with --resume.';
            } else {
                $this->run->checkpoint = null;
            }

            $this->finish($status);
        } catch (\Throwable $e) {
            $this->run->error = mb_substr($e->getMessage(), 0, 2000);
            $this->finish('failed');
            Log::error('[security:scan] scan failed', ['exception' => $e]);

            throw $e;
        }

        return $this->run;
    }

    /**
     * @param  array{abs: string, rel: string, link: bool}  $file
     */
    protected function processFile(array $file, string $mode): void
    {
        $rel = $file['rel'];
        $abs = $file['abs'];
        $this->seen[$rel] = true;
        $this->run->files_seen++;

        if ($file['link']) {
            $this->handleSymlink($abs, $rel);

            return;
        }

        $stat = @stat($abs);
        if ($stat === false || ! is_readable($abs)) {
            $this->recordError("Unreadable: {$rel}");

            return;
        }

        $size = (int) $stat['size'];
        $mtime = (int) $stat['mtime'];
        $known = $this->inventory[$rel] ?? null;
        $critical = $this->isCritical($rel);

        $unchanged = $known !== null && $known['scanned'] && ! $known['missing'] && $known['size'] === $size && $known['mtime'] === $mtime;
        if ($mode === 'incremental' && $unchanged) {
            $this->touchInventory($known['id']);

            return;
        }

        $sha = @hash_file('sha256', $abs);
        if ($sha === false) {
            $this->recordError("Hash failed: {$rel}");

            return;
        }

        $this->run->files_scanned++;
        if ($known === null || $known['sha256'] !== $sha) {
            $this->run->files_changed++;
        }

        $inUpload = $this->underAny($rel, config('security.scanner.upload_roots', []));

        // Integrity: critical files compared against their accepted baseline hash.
        if ($critical) {
            if ($known && $known['baseline_sha256'] && $known['baseline_sha256'] !== $sha) {
                $this->report($rel, $sha, 'integrity', 'integrity.changed', 80,
                    ['Critical file content changed since the accepted baseline.', 'Baseline: '.$known['baseline_sha256'], 'Current: '.$sha],
                    null, 'Compare with the deployed git revision (git diff). If the change is a legitimate deployment, use "Accept as baseline".');
            } elseif (! $known && $this->baselineExists) {
                $this->report($rel, $sha, 'integrity', 'integrity.new_file', 55,
                    ['New file appeared in an integrity-tracked location after the baseline was established.'],
                    null, 'Confirm the file belongs to a deployment; otherwise quarantine it and investigate how it was written.');
            }
        }

        // Any PHP-executable file directly in the public web root other than the front controller.
        $ext = strtolower(pathinfo($rel, PATHINFO_EXTENSION));
        if (str_starts_with($rel, 'public/') && ! in_array($rel, config('security.scanner.allowed_public_php', ['public/index.php']), true)
            && in_array($ext, HeuristicAnalyzer::SERVER_EXECUTABLE_EXTENSIONS, true)) {
            $this->report($rel, $sha, 'executable_public', 'public.executable_file', 75,
                ['Server-executable file inside the public web root (only public/index.php is expected).'],
                null, 'Quarantine unless it is a known, intentional entry point.');
        }

        if ($size <= (int) config('security.scanner.max_file_bytes')) {
            $content = @file_get_contents($abs);
            if ($content === false) {
                $this->recordError("Read failed: {$rel}");
            } else {
                $isConfig = in_array($rel, config('security.scanner.critical_files', []), true);
                $result = $this->analyzer->analyze($rel, $content, ['in_upload_root' => $inUpload, 'is_config_file' => $isConfig]);
                if ($result['confidence'] >= HeuristicAnalyzer::REPORT_THRESHOLD) {
                    $reasons = array_map(fn ($s) => "[{$s['rule']}] {$s['reason']}", $result['signals']);
                    $evidence = collect($result['signals'])->pluck('evidence')->filter()->first();
                    $this->report($rel, $sha, $result['category'], $result['rule'], $result['confidence'], $reasons, $evidence,
                        $this->remediationFor($result['category'], $inUpload), $inUpload);
                }
            }
        } else {
            $this->oversized++;
        }

        // Auto-quarantined files are no longer at this path: don't queue or inventory them as present.
        if (isset($this->quarantinedNow[$rel])) {
            return;
        }

        if ($this->clamav->isAvailable()) {
            $this->clamQueue[] = $abs;
        }

        $this->upsertInventory($rel, $sha, $size, $mtime, substr(sprintf('%o', $stat['mode']), -4), $critical, $known);
    }

    protected function handleSymlink(string $abs, string $rel): void
    {
        $target = @realpath($abs);
        if ($target === false) {
            $this->recordError("Dangling symlink: {$rel}");

            return;
        }
        $target = str_replace('\\', '/', $target);
        if (! str_starts_with($target.'/', $this->base.'/')) {
            $this->report($rel, null, 'symlink', 'symlink.escape', 70,
                ["Symbolic link points outside the application directory: {$target}"], null,
                'Remove the link unless it is part of the documented deployment (e.g. shared storage).');
        }
        // Links are never followed; in-project targets are scanned at their real location.
    }

    /**
     * @param  list<string>  $reasons
     */
    protected function report(string $rel, ?string $sha, string $category, string $rule, int $confidence, array $reasons, ?string $evidence, string $remediation, bool $inUpload = false): void
    {
        $severity = HeuristicAnalyzer::severityFor($confidence) ?? 'low';
        $this->reported[] = ['path' => $rel, 'severity' => $severity, 'rule' => $rule, 'confidence' => $confidence];
        $this->run->findings_count++;
        $this->say(sprintf('<fg=%s>[%s]</> %s  %s (%d%%)', $severity === 'critical' ? 'red' : 'yellow', strtoupper($severity), $rel, $rule, $confidence));

        if ($this->dryRun) {
            return;
        }

        $fingerprint = hash('sha256', $rel.'|'.$rule.'|'.($sha ?? ''));
        $finding = Finding::where('fingerprint', $fingerprint)->first();
        $now = now();

        if ($finding) {
            $finding->fill(['last_detected_at' => $now, 'scan_run_id' => $this->run->id, 'occurrences' => $finding->occurrences + 1]);
            if ($finding->status === 'resolved') {
                $finding->status = 'open';
                FindingEvent::create(['finding_id' => $finding->id, 'action' => 'reopened', 'note' => 'Detected again after being marked resolved.']);
            }
            $finding->save();
        } else {
            $finding = Finding::create([
                'fingerprint' => $fingerprint,
                'path' => $rel,
                'sha256' => $sha,
                'category' => $category,
                'rule' => $rule,
                'severity' => $severity,
                'confidence' => $confidence,
                'reasons' => $reasons,
                'evidence' => $evidence !== null ? mb_substr($evidence, 0, 1000) : null,
                'remediation' => $remediation,
                'status' => 'open',
                'first_detected_at' => $now,
                'last_detected_at' => $now,
                'scan_run_id' => $this->run->id,
            ]);
            FindingEvent::create(['finding_id' => $finding->id, 'action' => 'detected', 'meta' => ['scan_run_id' => $this->run->id]]);

            // Only signature engines "confirm" malware; heuristics are suspicions needing review.
            $eventType = match (true) {
                $category === 'integrity' => 'integrity_change',
                str_starts_with($rule, 'clamav.') || str_starts_with($rule, 'imunify.') => 'malware_confirmed',
                in_array($category, ['webshell', 'disguised_media', 'executable_upload', 'executable_public', 'persistence', 'obfuscation'], true) => 'malware_suspected',
                default => 'file_anomaly',
            };
            app(SecurityEventRecorder::class)->record($eventType, $severity,
                "{$rule} — {$rel}", ['finding_id' => $finding->id, 'path' => $rel, 'confidence' => $confidence, 'sha256' => $sha], 'logged');
        }

        $policy = config('security.scanner.auto_quarantine');
        if ($inUpload && ($policy['enabled'] ?? false) && $confidence >= ($policy['min_confidence'] ?? 90) && $finding->status === 'open') {
            try {
                $this->quarantine->quarantine($finding, null, 'auto: '.$rule);
                $this->say("  ↳ quarantined {$rel}");
                $this->quarantinedNow[$rel] = true;
            } catch (\Throwable $e) {
                $this->recordError("Auto-quarantine failed for {$rel}: ".$e->getMessage());
            }
        }
    }

    protected function flushClamQueue(): void
    {
        $queue = array_values(array_filter($this->clamQueue, 'is_file'));
        $this->clamQueue = [];
        if ($queue === []) {
            return;
        }

        $result = $this->clamav->scan($queue);
        if ($result['error'] !== null) {
            $this->recordError('ClamAV error: '.$result['error']);
        }
        foreach ($result['infected'] as $abs => $signature) {
            $abs = str_replace('\\', '/', $abs);
            $rel = ltrim(substr($abs, strlen($this->base)), '/');
            $this->report($rel, @hash_file('sha256', $abs) ?: null, 'malware', 'clamav.'.$signature, 99,
                ["ClamAV signature match: {$signature}"], null,
                'Quarantine immediately, preserve a copy for analysis, and investigate how it was written.',
                $this->underAny($rel, config('security.scanner.upload_roots', [])));
        }
    }

    /**
     * Deterministic depth-first walk with sorted entries; never follows symlinks.
     *
     * @return \Generator<array{abs: string, rel: string, link: bool}>
     */
    protected function walk(string $absPath): \Generator
    {
        $rel = $this->relative($absPath);
        if ($this->isExcluded($rel)) {
            return;
        }

        if (is_link($absPath)) {
            yield ['abs' => $absPath, 'rel' => $rel, 'link' => true];

            return;
        }

        if (is_file($absPath)) {
            yield ['abs' => $absPath, 'rel' => $rel, 'link' => false];

            return;
        }

        if (! is_dir($absPath)) {
            return;
        }

        $entries = @scandir($absPath);
        if ($entries === false) {
            $this->recordError("Unreadable directory: {$rel}");

            return;
        }

        foreach ($entries as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }
            yield from $this->walk($absPath.'/'.$entry);
        }
    }

    /**
     * @param  list<string>  $paths
     * @return array{0: list<string>, 1: list<string>}
     */
    protected function resolveTargets(string $mode, array $paths): array
    {
        if ($mode !== 'path') {
            $targets = [];
            $roots = [];
            foreach (config('security.scanner.roots', []) as $root) {
                $abs = $this->base.'/'.trim($root, '/');
                if (is_dir($abs)) {
                    $targets[] = $abs;
                    $roots[] = trim($root, '/');
                } else {
                    $this->gaps[] = "Configured root missing, not scanned: {$root}";
                }
            }
            $this->gaps[] = 'vendor/ and node_modules/ are not content-scanned; verify them with a clean `composer install` + diff.';

            return [$targets, $roots];
        }

        if ($paths === []) {
            throw new RuntimeException('Path mode requires at least one --path.');
        }

        $targets = [];
        foreach ($paths as $path) {
            $candidate = str_replace('\\', '/', $path);
            if (! preg_match('#^([a-zA-Z]:)?/#', $candidate)) {
                $candidate = $this->base.'/'.ltrim($candidate, '/');
            }
            // Canonicalise the parent so a not-yet-existing (deleted) file can still be checked.
            $real = file_exists($candidate) && ! is_link($candidate) ? realpath($candidate) : realpath(dirname($candidate));
            $real = $real === false ? false : str_replace('\\', '/', $real);
            if ($real === false || ! str_starts_with($real.'/', $this->base.'/')) {
                throw new RuntimeException("Path is outside the application directory: {$path}");
            }
            $targets[] = $candidate;
        }

        return [$targets, array_map(fn ($t) => $this->relative($t), $targets)];
    }

    /**
     * @param  list<string>  $roots
     */
    protected function detectDeleted(array $roots): void
    {
        foreach ($this->inventory as $rel => $row) {
            if (isset($this->seen[$rel]) || $row['missing'] || ! $this->underAny($rel, $roots) || $this->isExcluded($rel)) {
                continue;
            }
            $this->markMissing($rel, $row);
        }
    }

    /**
     * @param  list<string>  $paths
     */
    protected function detectDeletedExplicit(array $paths): void
    {
        foreach ($paths as $path) {
            $rel = $this->relative(preg_match('#^([a-zA-Z]:)?/#', str_replace('\\', '/', $path)) ? $path : $this->base.'/'.ltrim($path, '/'));
            $row = $this->inventory[$rel] ?? null;
            if ($row && ! $row['missing'] && ! file_exists($this->base.'/'.$rel)) {
                $this->markMissing($rel, $row);
            }
        }
    }

    protected function markMissing(string $rel, array $row): void
    {
        $this->run->files_deleted++;
        if (! $this->dryRun) {
            FileInventory::whereKey($row['id'])->update(['missing_since' => now()]);
        }
        if ($this->isCritical($rel)) {
            $this->report($rel, $row['sha256'], 'integrity', 'integrity.deleted', 70,
                ['Integrity-tracked file was deleted or renamed.'], null,
                'Confirm whether a deployment removed it; restore from git if not.');
        }
    }

    protected function loadInventory(): void
    {
        $this->inventory = [];
        FileInventory::query()
            ->select(['id', 'path', 'sha256', 'baseline_sha256', 'size', 'mtime', 'last_scanned_at', 'missing_since'])
            ->orderBy('id')
            ->chunk(2000, function ($rows) {
                foreach ($rows as $row) {
                    $this->inventory[$row->path] = [
                        'id' => $row->id,
                        'sha256' => $row->sha256,
                        'baseline_sha256' => $row->baseline_sha256,
                        'size' => (int) $row->size,
                        'mtime' => (int) $row->mtime,
                        'scanned' => $row->last_scanned_at !== null,
                        'missing' => $row->missing_since !== null,
                    ];
                }
            });
        $this->baselineExists = $this->inventory !== [];
    }

    protected function upsertInventory(string $rel, string $sha, int $size, int $mtime, string $perms, bool $critical, ?array $known): void
    {
        if ($this->dryRun) {
            return;
        }

        $now = now();
        if ($known) {
            FileInventory::whereKey($known['id'])->update([
                'sha256' => $sha, 'size' => $size, 'mtime' => $mtime, 'perms' => $perms, 'is_critical' => $critical,
                'last_seen_at' => $now, 'last_scanned_at' => $now, 'missing_since' => null,
                // A file that re-appears after deletion gets a fresh baseline only if it had none.
                'baseline_sha256' => $known['baseline_sha256'] ?? $sha,
            ]);
        } else {
            FileInventory::create([
                'path_hash' => FileInventory::hashPath($rel), 'path' => $rel, 'sha256' => $sha, 'baseline_sha256' => $sha,
                'size' => $size, 'mtime' => $mtime, 'perms' => $perms, 'is_critical' => $critical,
                'first_seen_at' => $now, 'last_seen_at' => $now, 'last_scanned_at' => $now,
            ]);
        }
    }

    protected function touchInventory(int $id): void
    {
        if ($this->dryRun) {
            return;
        }
        // Unchanged files are the vast majority of an incremental pass: batch their "seen" updates.
        $this->pendingTouches[] = $id;
        if (count($this->pendingTouches) >= 1000) {
            $this->flushTouches();
        }
    }

    protected function flushTouches(): void
    {
        foreach (array_chunk($this->pendingTouches, 1000) as $ids) {
            FileInventory::whereKey($ids)->update(['last_seen_at' => now()]);
        }
        $this->pendingTouches = [];
    }

    protected function finish(string $status): void
    {
        if ($this->pendingTouches !== []) {
            $this->flushTouches();
        }
        $this->run->status = $status;
        $this->run->finished_at = now();
        $this->run->coverage_gaps = array_values(array_unique($this->gaps));
        $this->persist($this->run);
    }

    protected function failStaleRuns(): void
    {
        if ($this->dryRun) {
            return;
        }
        ScanRun::where('status', 'running')
            ->where('started_at', '<', now()->subMinutes((int) config('security.scanner.stale_run_minutes', 120)))
            ->update(['status' => 'failed', 'error' => 'Worker stopped without finishing (stale run).', 'finished_at' => now()]);
    }

    protected function resumableRun(string $mode): ?ScanRun
    {
        // Only resume work newer than the last completed run; older checkpoints are superseded.
        $lastCompleted = (int) ScanRun::where('mode', $mode)->where('status', 'completed')->where('dry_run', false)->max('id');

        return ScanRun::where('mode', $mode)
            ->where('id', '>', $lastCompleted)
            ->whereIn('status', ['partial', 'failed'])
            ->whereNotNull('checkpoint')
            ->where('dry_run', false)
            ->latest('id')
            ->first();
    }

    protected function recordError(string $message): void
    {
        $this->run->errors_count++;
        if (count($this->gaps) < 100) {
            $this->gaps[] = $message;
        }
        $this->say("<fg=red>! {$message}</>");
    }

    protected function persist(ScanRun $run): void
    {
        if (! $this->dryRun) {
            $run->save();
        }
    }

    protected function overTimeBudget(): bool
    {
        return (microtime(true) - $this->startedAt) > (int) config('security.scanner.max_runtime_seconds', 1800);
    }

    protected function isCritical(string $rel): bool
    {
        if (in_array($rel, config('security.scanner.critical_files', []), true)) {
            return true;
        }

        return str_ends_with($rel, '.php') && $this->underAny($rel, config('security.scanner.critical_dirs', []));
    }

    protected function isExcluded(string $rel): bool
    {
        return $rel !== '' && $this->underAny($rel, config('security.scanner.exclude', []));
    }

    /**
     * @param  iterable<string>  $prefixes
     */
    protected function underAny(string $rel, iterable $prefixes): bool
    {
        foreach ($prefixes as $prefix) {
            $prefix = trim($prefix, '/');
            if ($rel === $prefix || str_starts_with($rel, $prefix.'/')) {
                return true;
            }
        }

        return false;
    }

    protected function relative(string $abs): string
    {
        $abs = str_replace('\\', '/', $abs);

        return ltrim(str_starts_with($abs, $this->base) ? substr($abs, strlen($this->base)) : $abs, '/');
    }

    /** Sort key matching depth-first walk order of scandir()-sorted entries. */
    public static function orderKey(string $rel): string
    {
        return str_replace('/', "\0", $rel);
    }

    protected function remediationFor(?string $category, bool $inUpload): string
    {
        return match ($category) {
            'webshell', 'disguised_media', 'executable_upload' => 'Do not open or execute. Quarantine the file, review web/access logs for requests to it, rotate credentials, and fix the upload path that allowed it.',
            'persistence' => 'Quarantine the config file, check for other handler overrides, and confirm PHP is disabled in upload directories.',
            'obfuscation' => 'Review manually: obfuscated PHP outside vendor/ is rarely legitimate. Compare with git history.',
            default => $inUpload ? 'Review and quarantine if not expected.' : 'Review the file and compare against version control.',
        };
    }

    protected function say(string $line): void
    {
        if ($this->output) {
            ($this->output)($line);
        }
    }

    protected function resetState(): void
    {
        $this->inventory = [];
        $this->seen = [];
        $this->clamQueue = [];
        $this->gaps = [];
        $this->reported = [];
        $this->quarantinedNow = [];
        $this->pendingTouches = [];
        $this->processed = 0;
        $this->oversized = 0;
    }

    /** @return list<array{path: string, severity: string, rule: string, confidence: int}> */
    public function reported(): array
    {
        return $this->reported;
    }
}
