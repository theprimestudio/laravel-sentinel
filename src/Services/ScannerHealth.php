<?php

namespace ThePrimeStudio\LaravelSentinel\Services;

use ThePrimeStudio\LaravelSentinel\Models\ScanRun;
use Illuminate\Support\Facades\Cache;

/**
 * Health of the scanning system, derived only from recorded state (runs, watcher heartbeat)
 * and cheap file-existence checks. It never launches a scan or a scanner process per request,
 * and never reports "monitoring active" without a fresh heartbeat from the watcher.
 */
class ScannerHealth
{
    public const HEARTBEAT_KEY = 'security:watcher:heartbeat';

    /**
     * @return array{overall: string, checks: list<array{name: string, status: string, message: string}>, gaps: list<string>}
     */
    public function report(): array
    {
        $checks = [];
        $add = function (string $name, string $status, string $message) use (&$checks) {
            $checks[] = compact('name', 'status', 'message');
        };

        // Watcher heartbeat
        $beat = Cache::get(self::HEARTBEAT_KEY);
        $maxAge = max(60, 4 * (int) config('security.scanner.watch_poll_seconds', 15));
        if (is_array($beat) && isset($beat['at']) && now()->timestamp - (int) $beat['at'] <= $maxAge) {
            $add('Real-time watcher', 'ok', 'Active ('.($beat['driver'] ?? 'unknown').'), last heartbeat '.now()->subSeconds(now()->timestamp - (int) $beat['at'])->diffForHumans().' on '.($beat['host'] ?? '?').'.');
        } else {
            $add('Real-time watcher', 'fail', 'NOT RUNNING — no heartbeat in the last '.$maxAge.'s. Start the security-scan-watch service (see deploy/).');
        }

        // Last full scan
        $lastFull = ScanRun::where('mode', 'full')->where('dry_run', false)->where('status', 'completed')->latest('id')->first();
        $maxHours = (int) config('security.scanner.full_scan_max_age_hours', 30);
        if (! $lastFull) {
            $add('Full scan', 'fail', 'No completed full scan recorded. Run: php artisan security:scan --mode=full');
        } elseif ($lastFull->finished_at?->lt(now()->subHours($maxHours))) {
            $add('Full scan', 'warn', 'Last completed full scan is older than '.$maxHours.'h ('.$lastFull->finished_at->diffForHumans().'). Is the scheduler (cron) running?');
        } else {
            $add('Full scan', 'ok', 'Completed '.$lastFull->finished_at?->diffForHumans().' (#'.$lastFull->id.').');
        }

        // Latest run outcome
        $last = ScanRun::where('dry_run', false)->latest('id')->first();
        if ($last && in_array($last->status, ['failed', 'partial'], true)) {
            $add('Latest run', $last->status === 'failed' ? 'fail' : 'warn',
                "Run #{$last->id} ({$last->mode}) ended {$last->status}".($last->error ? ': '.$last->error : '').' — results are NOT a clean bill of health.');
        } elseif ($last && $last->status === 'running' && $last->started_at?->lt(now()->subMinutes((int) config('security.scanner.stale_run_minutes', 120)))) {
            $add('Latest run', 'fail', "Run #{$last->id} has been 'running' since {$last->started_at} (worker likely died).");
        } elseif ($last) {
            $add('Latest run', 'ok', "Run #{$last->id} ({$last->mode}) {$last->status}.");
        }

        // Signature engine as observed by the last run (not probed per request)
        $clam = $last?->engines['clamav'] ?? null;
        if ($clam === null) {
            $add('ClamAV', 'warn', 'Unknown — no scan has run yet.');
        } elseif ($clam === 'unavailable') {
            $add('ClamAV', 'warn', 'Not available on the last run: signature-based malware detection is OFF; only heuristics ran.');
        } else {
            $add('ClamAV', 'ok', "Used by last run ({$clam}).");
        }

        // Cheap configuration exposure checks
        if (app()->environment('production') && config('app.debug')) {
            $add('Debug mode', 'fail', 'APP_DEBUG=true in production exposes stack traces and environment details.');
        } else {
            $add('Debug mode', 'ok', 'APP_DEBUG is off (or not production).');
        }

        $exposed = array_filter([
            public_path('.env'), public_path('.git'), public_path('composer.json'),
            ...glob(public_path('*.{sql,zip,tar,gz,bak}'), GLOB_BRACE) ?: [],
        ], 'file_exists');
        $add('Public web root exposure', $exposed === [] ? 'ok' : 'fail',
            $exposed === [] ? 'No .env/.git/backup files found in public/.' : 'Sensitive files in public/: '.implode(', ', array_map('basename', $exposed)));

        $add('Upload execution guard (Apache)', file_exists(storage_path('app/public/.htaccess')) ? 'ok' : 'warn',
            file_exists(storage_path('app/public/.htaccess')) ? 'storage/app/public/.htaccess present (nginx needs deploy/nginx-security.conf).' : 'storage/app/public/.htaccess missing — uploaded scripts may execute under Apache.');

        $q = (string) config('security.scanner.quarantine_path');
        $publicReal = realpath(public_path());
        $qReal = is_dir($q) ? realpath($q) : false;
        if ($qReal && $publicReal && str_starts_with($qReal, $publicReal)) {
            $add('Quarantine location', 'fail', 'Quarantine directory is inside the public web root.');
        } else {
            $add('Quarantine location', 'ok', 'Outside the web root'.(is_dir($q) ? '' : ' (created on first quarantine)').'.');
        }

        $statuses = array_column($checks, 'status');
        $overall = in_array('fail', $statuses, true) ? 'fail' : (in_array('warn', $statuses, true) ? 'warn' : 'ok');

        return [
            'overall' => $overall,
            'checks' => $checks,
            'gaps' => (array) ($lastFull?->coverage_gaps ?? $last?->coverage_gaps ?? []),
        ];
    }

    public static function beat(string $driver): void
    {
        // The inotify loop ticks 4x/second; persist at most every 15 seconds.
        static $lastWrite = 0;
        if (time() - $lastWrite < 15) {
            return;
        }
        $lastWrite = time();

        Cache::put(self::HEARTBEAT_KEY, ['at' => now()->timestamp, 'driver' => $driver, 'host' => gethostname() ?: null, 'pid' => getmypid()], 600);
    }
}
