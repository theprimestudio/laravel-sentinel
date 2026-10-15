<?php

namespace ThePrimeStudio\LaravelSentinel\Console;

use ThePrimeStudio\LaravelSentinel\Models\FileInventory;
use ThePrimeStudio\LaravelSentinel\Models\ScanRun;
use ThePrimeStudio\LaravelSentinel\Services\ClamAvScanner;
use ThePrimeStudio\LaravelSentinel\Services\ScanEngine;
use ThePrimeStudio\LaravelSentinel\Services\ScanLockedException;
use ThePrimeStudio\LaravelSentinel\Services\ScannerHealth;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\DB;
use Symfony\Component\Process\ExecutableFinder;
use Symfony\Component\Process\Process;

class SecurityScanCommand extends Command
{
    protected $signature = 'security:scan
        {--mode=incremental : full | incremental | watch}
        {--path=* : Scan only these files/directories (relative to the project or absolute inside it)}
        {--dry-run : Analyse and print findings without writing inventory, findings or quarantining}
        {--resume : Continue the last partial/failed run of the same mode from its checkpoint}
        {--max-files= : Stop after this many files (run is marked partial and resumable)}
        {--accept-baseline : Accept current hashes of present files as the trusted baseline (run after a verified deploy)}
        {--max-runtime=0 : Watch mode only: exit after N seconds so the supervisor restarts a fresh worker}
        {--status : Print scanner health and exit}';

    protected $description = 'Scan application, upload and storage files for web shells, malware and unauthorised changes';

    protected bool $stop = false;

    public function handle(ScanEngine $engine, ClamAvScanner $clamav): int
    {
        if ($this->option('status')) {
            return $this->printStatus($clamav);
        }

        if ($this->option('accept-baseline')) {
            return $this->acceptBaseline();
        }

        $mode = $this->option('path') ? 'path' : (string) $this->option('mode');

        if ($mode === 'watch') {
            return $this->watch($engine);
        }

        if (! in_array($mode, ['full', 'incremental', 'path'], true)) {
            $this->error("Unknown mode [{$mode}]. Use full, incremental or watch.");

            return self::INVALID;
        }

        return $this->runOnce($engine, [
            'mode' => $mode,
            'paths' => $this->option('path'),
            'dry_run' => (bool) $this->option('dry-run'),
            'resume' => (bool) $this->option('resume'),
            'max_files' => $this->option('max-files') ? (int) $this->option('max-files') : null,
        ]);
    }

    protected function runOnce(ScanEngine $engine, array $options): int
    {
        $options['output'] = fn (string $line) => $this->line($line);

        try {
            $run = $engine->run($options);
        } catch (ScanLockedException $e) {
            $this->warn($e->getMessage());

            return 2;
        } catch (\Throwable $e) {
            $this->error('Scan FAILED: '.$e->getMessage());
            $this->error('Result: NOT CLEAN (scan did not complete).');

            return self::FAILURE;
        }

        $this->newLine();
        $this->table(['Status', 'Mode', 'Seen', 'Scanned', 'Changed', 'Deleted', 'Findings', 'Errors', 'Engines'], [[
            strtoupper($run->status).($run->dry_run ? ' (dry-run)' : ''), $run->mode, $run->files_seen, $run->files_scanned,
            $run->files_changed, $run->files_deleted, $run->findings_count, $run->errors_count,
            collect($run->engines)->map(fn ($v, $k) => "{$k}:{$v}")->implode(' '),
        ]]);

        foreach ((array) $run->coverage_gaps as $gap) {
            $this->warn('Coverage gap: '.$gap);
        }

        if ($run->status !== 'completed') {
            $this->error('Result: NOT VERIFIED CLEAN — run was '.$run->status.'.');

            return 2;
        }

        $serious = collect($engine->reported())->whereIn('severity', ['critical', 'high'])->count();
        if ($serious > 0) {
            $this->error("{$serious} critical/high finding(s).");

            return self::FAILURE;
        }

        $this->info($run->findings_count > 0 ? 'Completed with lower-severity findings.' : 'Completed: no findings from the engines that ran.');

        return self::SUCCESS;
    }

    /**
     * Event-driven watcher. Uses inotifywait on Linux when installed; otherwise polls with cheap
     * stat-only incremental scans. Full scans are left to the scheduler (never per event).
     */
    protected function watch(ScanEngine $engine): int
    {
        $this->trapSignals();
        $deadline = (int) $this->option('max-runtime') > 0 ? time() + (int) $this->option('max-runtime') : null;
        $poll = max(5, (int) config('security.scanner.watch_poll_seconds', 15));
        $debounce = max(1, (int) config('security.scanner.watch_debounce_seconds', 2));
        $safetyNet = 600; // incremental pass every 10 min even with inotify (covers dropped events)

        $bin = (string) config('security.scanner.inotifywait', 'inotifywait');
        $inotifyPath = PHP_OS_FAMILY === 'Linux' ? (new ExecutableFinder)->find($bin) : null;

        $this->info('security:scan watcher started ('.($inotifyPath ? 'inotify' : "polling every {$poll}s").').');
        $this->runQuiet($engine, ['mode' => 'incremental']);
        $lastIncremental = time();

        $process = $inotifyPath ? $this->startInotify($inotifyPath) : null;
        $pending = [];
        $lastEventAt = 0;
        $buffer = '';

        while (! $this->stop && ($deadline === null || time() < $deadline)) {
            ScannerHealth::beat($process ? 'inotify' : 'polling');
            if ($process) {
                if (! $process->isRunning()) {
                    $this->warn('inotifywait exited ('.trim($process->getErrorOutput()).'); falling back to polling.');
                    $process = null;

                    continue;
                }
                $buffer .= $process->getIncrementalOutput();
                while (($nl = strpos($buffer, "\n")) !== false) {
                    $path = trim(substr($buffer, 0, $nl));
                    $buffer = substr($buffer, $nl + 1);
                    if ($path !== '' && ! str_ends_with($path, '/')) {
                        $pending[$path] = true;
                        $lastEventAt = time();
                    }
                }

                if ($pending && time() - $lastEventAt >= $debounce) {
                    foreach (array_chunk(array_keys($pending), 500) as $chunk) {
                        $this->runQuiet($engine, ['mode' => 'path', 'paths' => $chunk, 'lock_wait' => 30]);
                    }
                    $pending = [];
                }

                if (time() - $lastIncremental >= $safetyNet) {
                    $this->runQuiet($engine, ['mode' => 'incremental']);
                    $lastIncremental = time();
                }

                usleep(250000);
            } else {
                $this->sleepInterruptibly($poll);
                $this->runQuiet($engine, ['mode' => 'incremental']);
            }
        }

        $process?->stop(3);
        $this->info('security:scan watcher stopped.');

        return self::SUCCESS;
    }

    protected function startInotify(string $bin): Process
    {
        $base = rtrim(str_replace('\\', '/', base_path()), '/');
        $roots = collect(config('security.scanner.roots', []))
            ->map(fn ($r) => $base.'/'.trim($r, '/'))
            ->filter(fn ($p) => is_dir($p))
            ->values()->all();
        $exclude = collect(config('security.scanner.exclude', []))
            ->map(fn ($e) => preg_quote($base.'/'.trim($e, '/'), '#'))
            ->implode('|');

        $process = new Process(array_merge(
            [$bin, '-m', '-r', '-q', '-e', 'close_write,create,moved_to,moved_from,delete,attrib',
                '--format', '%w%f', '--exclude', '^('.$exclude.')(/|$)'],
            $roots
        ));
        $process->setTimeout(null);
        $process->start();

        return $process;
    }

    protected function runQuiet(ScanEngine $engine, array $options): void
    {
        try {
            $run = $engine->run($options + ['output' => fn (string $line) => $this->line($line)]);
            if ($run->findings_count > 0 || $run->status !== 'completed') {
                $this->line(sprintf('[%s] %s run #%s: %s, %d finding(s), %d error(s)',
                    now()->toDateTimeString(), $run->mode, $run->id ?? '-', $run->status, $run->findings_count, $run->errors_count));
            }
        } catch (ScanLockedException) {
            // Another scan (e.g. scheduled full scan) is running; the next tick will catch up.
        } catch (\Throwable $e) {
            $this->error('['.now()->toDateTimeString().'] scan failed: '.$e->getMessage());
        }
    }

    protected function acceptBaseline(): int
    {
        $count = FileInventory::whereNull('missing_since')
            ->whereColumn('baseline_sha256', '!=', 'sha256')
            ->update(['baseline_sha256' => DB::raw('sha256')]);
        $this->info("Baseline accepted for {$count} changed file(s). Run a scan first so hashes are current.");

        return self::SUCCESS;
    }

    protected function printStatus(ClamAvScanner $clamav): int
    {
        $status = $clamav->status();
        $lastFull = ScanRun::where('mode', 'full')->where('dry_run', false)->latest('id')->first();
        $last = ScanRun::where('dry_run', false)->latest('id')->first();
        $inotify = PHP_OS_FAMILY === 'Linux' ? (new ExecutableFinder)->find((string) config('security.scanner.inotifywait')) : null;

        $this->table(['Check', 'Value'], [
            ['ClamAV', $status['available'] ? "{$status['engine']} ({$status['version']})" : 'UNAVAILABLE — '.$status['reason']],
            ['inotify', $inotify ?: 'unavailable (watch mode will poll)'],
            ['Last run', $last ? "#{$last->id} {$last->mode} {$last->status} at {$last->finished_at}" : 'never'],
            ['Last full run', $lastFull ? "#{$lastFull->id} {$lastFull->status} at {$lastFull->finished_at}" : 'never'],
            ['Inventory files', FileInventory::whereNull('missing_since')->count()],
        ]);

        return self::SUCCESS;
    }

    protected function trapSignals(): void
    {
        if (function_exists('pcntl_async_signals')) {
            pcntl_async_signals(true);
            pcntl_signal(SIGTERM, fn () => $this->stop = true);
            pcntl_signal(SIGINT, fn () => $this->stop = true);
        }
    }

    protected function sleepInterruptibly(int $seconds): void
    {
        for ($i = 0; $i < $seconds * 4 && ! $this->stop; $i++) {
            usleep(250000);
        }
    }
}
