<?php

namespace ThePrimeStudio\LaravelSentinel\Console;

use ThePrimeStudio\LaravelSentinel\Models\ContentBackup;
use ThePrimeStudio\LaravelSentinel\Models\Finding;
use ThePrimeStudio\LaravelSentinel\Services\ContentSecurityScanner;
use Illuminate\Console\Command;

class SecurityScanContentCommand extends Command
{
    protected $signature = 'security:scan-content
        {--dry-run : Report only; do not record findings}
        {--table= : Limit to one configured table}
        {--report= : Also write a CSV report to this path}
        {--apply= : Sanitise the record of this finding id (backup kept)}
        {--rollback= : Restore the original value from this backup id}';

    protected $description = 'Review stored database content for XSS / injected markup (never deletes; cleanup is per finding and reversible)';

    public function handle(ContentSecurityScanner $scanner): int
    {
        if ($id = $this->option('apply')) {
            $backup = $scanner->applySanitized(Finding::findOrFail($id));
            $this->info("Sanitised finding #{$id}. Backup #{$backup->id} (rollback: --rollback={$backup->id}).");

            return self::SUCCESS;
        }
        if ($id = $this->option('rollback')) {
            $scanner->restore(ContentBackup::findOrFail($id), null, 'CLI rollback');
            $this->warn("Original content restored from backup #{$id}. It is the UNSANITISED value — review it.");

            return self::SUCCESS;
        }

        $result = $scanner->scan(['dry_run' => (bool) $this->option('dry-run'), 'table' => $this->option('table')]);

        $this->table(['Severity', 'Location', 'Kind', 'Reasons'], array_map(fn ($r) => [
            strtoupper($r['severity']), ContentSecurityScanner::pathFor($r), $r['kind'], implode(', ', $r['reasons']),
        ], $result['rows']));
        foreach ($result['gaps'] as $gap) {
            $this->warn('Skipped: '.$gap);
        }
        $this->info("{$result['scanned']} record(s) reviewed, ".count($result['rows']).' suspicious value(s)'.($this->option('dry-run') ? ' (dry-run: nothing recorded).' : ' recorded as findings.'));

        if ($path = $this->option('report')) {
            $fh = fopen($path, 'w');
            fputcsv($fh, ['severity', 'location', 'kind', 'reasons', 'sha256']);
            foreach ($result['rows'] as $r) {
                fputcsv($fh, [$r['severity'], ContentSecurityScanner::pathFor($r), $r['kind'], implode('; ', $r['reasons']), $r['sha256']]);
            }
            fclose($fh);
            $this->info("Report written to {$path}");
        }

        return collect($result['rows'])->whereIn('severity', ['critical', 'high'])->isNotEmpty() ? self::FAILURE : self::SUCCESS;
    }
}
