<?php

namespace ThePrimeStudio\LaravelSentinel\Services;

use ThePrimeStudio\LaravelSentinel\Models\ContentBackup;
use ThePrimeStudio\LaravelSentinel\Models\Finding;
use ThePrimeStudio\LaravelSentinel\Models\FindingEvent;
// Host User decoupled
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Str;
use RuntimeException;

/**
 * Reviews stored database content for XSS / injected markup.
 *
 * Detection never modifies data. Cleanup is per finding, explicit and reversible:
 * the current value must still match the hash seen at detection time, the original is
 * backed up, and the sanitised value is written through the model (so caches and audit
 * columns stay consistent). Plain-text fields are only reported: they are escaped on
 * output, so rewriting them could damage legitimate text.
 */
class ContentSecurityScanner
{
    public static array $models = [];

    public function __construct(protected HtmlSanitizer $sanitizer, protected SecurityEventRecorder $recorder) {}

    /**
     * @param  array{dry_run?: bool, since?: ?\DateTimeInterface, table?: ?string}  $options
     * @return array{rows: list<array>, gaps: list<string>, scanned: int}
     */
    public function scan(array $options = []): array
    {
        $dry = (bool) ($options['dry_run'] ?? false);
        $since = $options['since'] ?? null;
        $rows = [];
        $gaps = [];
        $scanned = 0;

        foreach (config('security.content_sources', []) as $source) {
            if (($options['table'] ?? null) && $source['table'] !== $options['table']) {
                continue;
            }
            if (! Schema::hasTable($source['table']) || ! Schema::hasColumn($source['table'], $source['field'])) {
                $gaps[] = "{$source['table']}.{$source['field']} not present — skipped";

                continue;
            }

            $query = DB::table($source['table'])->select(array_unique([$source['key'], $source['field']]));
            if ($source['type'] === 'setting') {
                $query->addSelect('type');
            }
            if ($since && Schema::hasColumn($source['table'], 'updated_at')) {
                $query->where('updated_at', '>=', $since);
            }

            $query->orderBy($source['key'])->chunk(500, function ($records) use ($source, $dry, &$rows, &$scanned) {
                foreach ($records as $record) {
                    $scanned++;
                    foreach ($this->inspectRecord($source, (array) $record) as $hit) {
                        $rows[] = $hit;
                        if (! $dry) {
                            $this->recordFinding($hit);
                        }
                    }
                }
            });
        }

        return ['rows' => $rows, 'gaps' => $gaps, 'scanned' => $scanned];
    }

    /** @return list<array> */
    protected function inspectRecord(array $source, array $record): array
    {
        $value = $record[$source['field']] ?? null;
        if (! is_string($value) || $value === '') {
            return [];
        }
        $key = (string) $record[$source['key']];
        $base = ['table' => $source['table'], 'key' => $key, 'field' => $source['field']];

        $type = $source['type'];
        if ($type === 'setting') {
            $type = ($record['type'] ?? null) === 'rich_text' ? 'html' : 'text';
        }

        if ($type === 'blocks') {
            $hits = [];
            foreach ((array) json_decode($value, true) as $i => $block) {
                if (! is_array($block) || ! is_string($block['value'] ?? null)) {
                    continue;
                }
                $blockType = strtolower((string) ($block['type'] ?? 'text')) === 'richtext' ? 'html' : 'text';
                if ($hit = $this->evaluate($block['value'], $blockType, $base + ['block' => (string) ($block['key'] ?? $i)])) {
                    $hits[] = $hit;
                }
            }

            return $hits;
        }

        return ($hit = $this->evaluate($value, $type, $base)) ? [$hit] : [];
    }

    protected function evaluate(string $value, string $type, array $location): ?array
    {
        $reasons = $this->sanitizer->detect($value);
        if ($reasons === []) {
            return null;
        }

        $executable = (bool) array_intersect($reasons, ['script element', 'inline event handler (on*=)', 'javascript:/vbscript: URL', 'obfuscated javascript: URL', 'data:text/html or data:*script URL', 'iframe/frame element', 'embedded object/applet/embed', 'SVG/MathML markup']);
        // HTML fields are rendered raw ({!! !!}); text fields are escaped, so lower risk.
        $confidence = $type === 'html' ? ($executable ? 92 : 70) : ($executable ? 55 : 40);

        return $location + [
            'kind' => $type,
            'reasons' => $reasons,
            'confidence' => $confidence,
            'severity' => HeuristicAnalyzer::severityFor($confidence) ?? 'low',
            'sha256' => hash('sha256', $value),
            'excerpt' => $this->excerpt($value, $reasons),
        ];
    }

    protected function recordFinding(array $hit): void
    {
        $path = self::pathFor($hit);
        $rule = 'content.'.Str::slug($hit['reasons'][0], '_');
        $fingerprint = hash('sha256', $path.'|'.$rule.'|'.$hit['sha256']);
        $finding = Finding::where('fingerprint', $fingerprint)->first();

        if ($finding) {
            $finding->update(['last_detected_at' => now(), 'occurrences' => $finding->occurrences + 1]);

            return;
        }

        $finding = Finding::create([
            'fingerprint' => $fingerprint,
            'path' => $path,
            'sha256' => $hit['sha256'],
            'category' => $hit['kind'] === 'html' ? 'stored_xss' : 'suspicious_content',
            'rule' => $rule,
            'severity' => $hit['severity'],
            'confidence' => $hit['confidence'],
            'reasons' => array_map(fn ($r) => "Stored content contains: {$r}", $hit['reasons']),
            'evidence' => $hit['excerpt'],
            'remediation' => $hit['kind'] === 'html'
                ? 'Review the record. If the markup is not intentional, use "Apply sanitised version" (original is backed up and can be restored). Then find out which account wrote it (activity log).'
                : 'This field is escaped on output, so it is not directly executable. Edit the record manually if the text is unwanted; it is never rewritten automatically.',
            'status' => 'open',
            'first_detected_at' => now(),
            'last_detected_at' => now(),
        ]);
        FindingEvent::create(['finding_id' => $finding->id, 'action' => 'detected', 'meta' => ['source' => 'content_scan']]);
        $this->recorder->record('stored_xss', $hit['severity'], 'Stored content anomaly in '.$path.': '.implode(', ', $hit['reasons']),
            ['finding_id' => $finding->id, 'table' => $hit['table'], 'record' => $hit['key'], 'field' => $hit['field']], 'logged');
    }

    /** Sanitise one content finding in place, keeping a backup. */
    public function applySanitized(Finding $finding, ?object $user = null): ContentBackup
    {
        $loc = self::parsePath($finding->path);
        $modelClass = self::MODELS[$loc['table']] ?? null;
        if ($finding->category !== 'stored_xss' || ! $modelClass) {
            throw new RuntimeException('Only stored-XSS findings in HTML fields can be sanitised automatically.');
        }

        return DB::transaction(function () use ($finding, $loc, $modelClass, $user) {
            $model = $modelClass::query()->whereKey($loc['key'])->lockForUpdate()->firstOrFail();
            $raw = (string) $model->getRawOriginal($loc['field']);

            if (isset($loc['block'])) {
                $blocks = (array) json_decode($raw, true);
                $index = collect($blocks)->search(fn ($b, $i) => (string) ($b['key'] ?? $i) === $loc['block']);
                $current = $index === false ? null : ($blocks[$index]['value'] ?? null);
                if (! is_string($current) || hash('sha256', $current) !== $finding->sha256) {
                    throw new RuntimeException('The content changed since detection; re-scan before applying.');
                }
                $blocks[$index]['value'] = (string) $this->sanitizer->sanitize($current, 'rich');
                $sanitizedField = json_encode($blocks, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
                $model->{$loc['field']} = $blocks;                 // cast sanitises again (idempotent)
            } else {
                if (hash('sha256', $raw) !== $finding->sha256) {
                    throw new RuntimeException('The content changed since detection; re-scan before applying.');
                }
                $sanitizedField = (string) $this->sanitizer->sanitize($raw, 'rich');
                $model->{$loc['field']} = $sanitizedField;
            }

            $backup = ContentBackup::create([
                'finding_id' => $finding->id, 'table_name' => $loc['table'], 'record_key' => $loc['key'],
                'field' => $loc['field'], 'original' => $raw, 'sanitized' => $sanitizedField,
                'original_sha256' => hash('sha256', $raw), 'applied_by' => $user?->id, 'applied_at' => now(),
            ]);
            $model->save();
            $this->flushCaches($modelClass);

            $finding->update(['status' => 'resolved', 'resolved_by' => $user?->id, 'resolved_at' => now()]);
            FindingEvent::create(['finding_id' => $finding->id, 'user_id' => $user?->id, 'action' => 'content_sanitized', 'meta' => ['backup_id' => $backup->id]]);

            return $backup;
        });
    }

    /** Put the original (pre-cleanup) value back. Bypasses the sanitiser deliberately; audited. */
    public function restore(ContentBackup $backup, ?object $user = null, ?string $note = null): void
    {
        if ($backup->restored_at) {
            throw new RuntimeException('This backup was already restored.');
        }
        $modelClass = self::MODELS[$backup->table_name] ?? throw new RuntimeException('Unknown table.');

        DB::transaction(function () use ($backup, $modelClass, $user, $note) {
            $current = DB::table($backup->table_name)->where('id', $backup->record_key)->lockForUpdate()->value($backup->field);
            if ($current === null) {
                throw new RuntimeException('Record no longer exists.');
            }
            DB::table($backup->table_name)->where('id', $backup->record_key)->update([$backup->field => $backup->original]);
            $this->flushCaches($modelClass);
            $backup->update(['restored_by' => $user?->id, 'restored_at' => now()]);
            if ($backup->finding) {
                $backup->finding->update(['status' => 'acknowledged']);
                FindingEvent::create(['finding_id' => $backup->finding_id, 'user_id' => $user?->id, 'action' => 'content_restored', 'note' => $note, 'meta' => ['backup_id' => $backup->id]]);
            }
            $this->recorder->record('content_restored', 'medium', "Original (unsanitised) content restored for {$backup->table_name}#{$backup->record_key}.{$backup->field}",
                ['backup_id' => $backup->id], 'logged');
        });
    }

    protected function flushCaches(string $modelClass): void
    {
        if (method_exists($modelClass, 'flushModelCache')) {
            $modelClass::flushModelCache();
        }
        Cache::forget('settings.all');
    }

    public static function pathFor(array $hit): string
    {
        return "db://{$hit['table']}/{$hit['key']}/{$hit['field']}".(isset($hit['block']) ? '#'.$hit['block'] : '');
    }

    /** @return array{table: string, key: string, field: string, block?: string} */
    public static function parsePath(string $path): array
    {
        if (! preg_match('#^db://([a-z_]+)/([^/]+)/([a-z_]+)(?:\#(.+))?$#', $path, $m)) {
            throw new RuntimeException('Not a database content finding.');
        }

        return array_filter(['table' => $m[1], 'key' => $m[2], 'field' => $m[3], 'block' => $m[4] ?? null], fn ($v) => $v !== null);
    }

    protected function excerpt(string $value, array $reasons): string
    {
        $needles = ['<script', 'onerror', 'onload', 'javascript:', '<iframe', '<svg', '<object', '<embed', '<?php', 'on'];
        $pos = 0;
        foreach ($needles as $n) {
            if (($p = stripos($value, $n)) !== false) {
                $pos = $p;
                break;
            }
        }

        return mb_substr(substr($value, max(0, $pos - 80), 400), 0, 400);
    }
}
