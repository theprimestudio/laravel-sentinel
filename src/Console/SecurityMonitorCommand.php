<?php

namespace ThePrimeStudio\LaravelSentinel\Console;

use ThePrimeStudio\LaravelSentinel\Models\Finding;
use ThePrimeStudio\LaravelSentinel\Models\FindingEvent;
use ThePrimeStudio\LaravelSentinel\Models\SecurityEvent;
use ThePrimeStudio\LaravelSentinel\Services\ContentSecurityScanner;
use ThePrimeStudio\LaravelSentinel\Services\ScannerHealth;
use ThePrimeStudio\LaravelSentinel\Services\SecurityEventRecorder;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Symfony\Component\Process\ExecutableFinder;
use Symfony\Component\Process\Process;

/**
 * Lightweight periodic checks (scheduled every 5 minutes). Expensive work — full file scans,
 * full content scans — is scheduled separately and never runs here.
 */
class SecurityMonitorCommand extends Command
{
    protected $signature = 'security:monitor {--skip-imunify : Do not query Imunify360 this run}';

    protected $description = 'Detect auth anomalies, content changes, scanner/notification failures and event-log tampering';

    public const STATUS_KEY = 'security:monitor:status';

    public function handle(SecurityEventRecorder $recorder, ContentSecurityScanner $content, ScannerHealth $health): int
    {
        $status = ['ran_at' => now()->timestamp];

        $status['auth'] = $this->authAnomalies($recorder);

        // Content written since the last run (covers paths that bypass Eloquent casts and set updated_at).
        $since = Cache::get('security:monitor:content_since');
        $result = $content->scan(['since' => $since ? now()->setTimestamp($since) : now()->subDay()]);
        Cache::forever('security:monitor:content_since', now()->subMinute()->timestamp);
        $status['content'] = ['scanned' => $result['scanned'], 'suspicious' => count($result['rows'])];

        // Scanner health failures become incidents (deduplicated by fingerprint).
        foreach ($health->report()['checks'] as $check) {
            if ($check['status'] === 'fail') {
                $recorder->record('scanner_health', 'high', "{$check['name']}: {$check['message']}", [], 'logged', '127.0.0.1');
            }
        }

        // Notification delivery failures (queue/mail).
        if (Schema::hasTable('failed_jobs')) {
            $failed = DB::table('failed_jobs')->where('failed_at', '>=', now()->subMinutes(15))
                ->where('payload', 'like', '%SecurityIncidentNotification%')->count();
            if ($failed > 0) {
                $recorder->record('notification_failure', 'medium', "{$failed} security notification job(s) failed in the last 15 minutes", [], 'logged', '127.0.0.1');
            }
            $status['failed_notifications'] = $failed;
        }

        // Tamper evidence: verify the recent hash chain.
        $chain = $recorder->verifyChain(2000);
        $status['chain'] = $chain;
        if (! $chain['ok']) {
            $recorder->record('log_tamper', 'critical', "Security event hash chain broken at event #{$chain['broken_at']} (events edited or deleted outside the application)", $chain, 'logged', '127.0.0.1');
        }

        if (! $this->option('skip-imunify')) {
            $status['imunify'] = $this->imunify($recorder);
        }

        $status['pruned'] = $this->prune();
        Cache::forever(self::STATUS_KEY, $status);

        $this->info(sprintf('Monitor ok: auth=%s content=%d/%d chain=%s imunify=%s',
            json_encode($status['auth']), $status['content']['suspicious'], $status['content']['scanned'],
            $chain['ok'] ? 'ok' : 'BROKEN', $status['imunify']['state'] ?? 'skipped'));

        return self::SUCCESS;
    }

    protected function authAnomalies(SecurityEventRecorder $recorder): array
    {
        $window = (int) config('security.monitoring.window_minutes', 15);
        $events = SecurityEvent::query()
            ->whereIn('type', ['failed_login', 'lockout'])
            ->where('occurred_at', '>=', now()->subMinutes($window))
            ->get(['source_ip', 'context']);

        $found = ['brute_force' => 0, 'credential_stuffing' => 0];
        foreach ($events->groupBy('source_ip') as $ip => $group) {
            if ($ip === '') {
                continue;
            }
            $accounts = $group->pluck('context.identifier')->filter()->unique()->count();
            if ($accounts >= (int) config('security.monitoring.distinct_accounts_per_ip', 5)) {
                $recorder->record('credential_stuffing', 'high', "Failed logins for {$accounts} different accounts from one IP within {$window} min", ['attempts' => $group->count(), 'accounts' => $accounts], 'logged', $ip);
                $found['credential_stuffing']++;
            } elseif ($group->count() >= (int) config('security.monitoring.failed_logins_per_ip', 10)) {
                $recorder->record('brute_force', 'high', "{$group->count()} failed logins from one IP within {$window} min", ['attempts' => $group->count()], 'logged', $ip);
                $found['brute_force']++;
            }
        }

        return $found;
    }

    /** Import Imunify360 malware detections when the agent is installed (signature-based → "confirmed"). */
    protected function imunify(SecurityEventRecorder $recorder): array
    {
        $cfg = config('security.monitoring.imunify', []);
        $bin = ($cfg['enabled'] ?? true) ? (new ExecutableFinder)->find((string) ($cfg['binary'] ?? 'imunify360-agent')) : null;
        if (! $bin) {
            return ['state' => 'not_installed'];
        }

        try {
            $process = new Process([$bin, 'malware', 'malicious', 'list', '--json', '--limit', '500']);
            $process->setTimeout(60)->run();
            if (! $process->isSuccessful()) {
                $recorder->record('scanner_health', 'medium', 'Imunify360 query failed: '.trim($process->getErrorOutput()), [], 'logged', '127.0.0.1');

                return ['state' => 'error'];
            }
            $items = json_decode($process->getOutput(), true);
            $items = $items['items'] ?? $items['data'] ?? $items;
        } catch (\Throwable $e) {
            return ['state' => 'error', 'error' => $e->getMessage()];
        }

        $base = rtrim(str_replace('\\', '/', base_path()), '/').'/';
        $imported = 0;
        foreach ((array) $items as $item) {
            $file = str_replace('\\', '/', (string) ($item['file'] ?? $item['path'] ?? ''));
            if ($file === '' || ! str_starts_with($file, $base)) {
                continue;   // only this application's files
            }
            $rel = substr($file, strlen($base));
            $signature = (string) ($item['type'] ?? $item['signature'] ?? 'detected');
            $fingerprint = hash('sha256', $rel.'|imunify.'.$signature.'|'.($item['hash'] ?? ''));
            if (Finding::where('fingerprint', $fingerprint)->exists()) {
                continue;
            }
            $finding = Finding::create([
                'fingerprint' => $fingerprint, 'path' => $rel, 'sha256' => $item['hash'] ?? null,
                'category' => 'malware', 'rule' => 'imunify.'.$signature, 'severity' => 'critical', 'confidence' => 98,
                'reasons' => ["Imunify360 signature detection: {$signature}"], 'remediation' => 'Confirmed by Imunify360 signature. Quarantine, investigate how it was written, rotate credentials.',
                'status' => 'open', 'first_detected_at' => now(), 'last_detected_at' => now(),
            ]);
            FindingEvent::create(['finding_id' => $finding->id, 'action' => 'detected', 'meta' => ['source' => 'imunify360']]);
            $recorder->record('malware_confirmed', 'critical', "Imunify360: {$signature} — {$rel}", ['finding_id' => $finding->id], 'logged', '127.0.0.1');
            $imported++;
        }

        return ['state' => 'ok', 'imported' => $imported];
    }

    /** Retention: drop events older than the configured window (the chain is verified from the oldest kept event). */
    protected function prune(): int
    {
        $days = (int) config('security.events.retention_days', 365);
        if ($days <= 0) {
            return 0;
        }

        // Bounded batch, portable across MySQL/MariaDB/SQLite (no DELETE ... LIMIT).
        $ids = DB::table('security_events')->where('occurred_at', '<', now()->subDays($days))->orderBy('id')->limit(5000)->pluck('id');

        return $ids->isEmpty() ? 0 : DB::table('security_events')->whereIn('id', $ids)->delete();
    }
}
