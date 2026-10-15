<?php

namespace ThePrimeStudio\LaravelSentinel\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class SecurityTxt extends Model
{
    protected $table = 'security_txt';

    protected $guarded = [];

    protected $casts = [
        'expires_at' => 'datetime',
    ];

    public function updatedBy(): BelongsTo
    {
        $userModel = config('security.auth.user_model', 'App\\Models\\User');
        return $this->belongsTo($userModel, 'updated_by');
    }

    /** Render the RFC 9116 document. Every value was validated as a single-line URI/tag list. */
    public function render(): string
    {
        $host = parse_url((string) config('app.url'), PHP_URL_HOST) ?: 'localhost';
        $lines = [
            '# Security contact information for '.$host,
            '# Format: RFC 9116 (https://www.rfc-editor.org/rfc/rfc9116)',
            '',
        ];
        foreach (self::splitLines($this->contacts) as $v) {
            $lines[] = 'Contact: '.$v;
        }
        $lines[] = 'Expires: '.$this->expires_at->copy()->utc()->format('Y-m-d\TH:i:s.000\Z');
        foreach (['encryption' => 'Encryption', 'acknowledgments' => 'Acknowledgments', 'policy' => 'Policy', 'hiring' => 'Hiring', 'canonical' => 'Canonical'] as $field => $label) {
            foreach (self::splitLines($this->{$field}) as $v) {
                $lines[] = "{$label}: {$v}";
            }
        }
        if ($this->preferred_languages) {
            $lines[] = 'Preferred-Languages: '.$this->preferred_languages;
        }

        return implode("\n", $lines)."\n";
    }

    /** @return list<string> */
    public static function splitLines(?string $value): array
    {
        return array_values(array_filter(array_map('trim', preg_split('/\R/', (string) $value) ?: [])));
    }
}