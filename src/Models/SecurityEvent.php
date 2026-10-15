<?php

namespace ThePrimeStudio\LaravelSentinel\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use RuntimeException;

/** Append-only security event. Updates and deletes through Eloquent are refused. */
class SecurityEvent extends Model
{
    public const UPDATED_AT = null;

    protected $table = 'security_events';

    protected $guarded = [];

    protected $casts = [
        'context' => 'array',
        'occurred_at' => 'datetime',
    ];

    protected static function booted(): void
    {
        static::updating(fn () => throw new RuntimeException('Security events are append-only.'));
        static::deleting(fn () => throw new RuntimeException('Security events are append-only.'));
    }

    public function user(): BelongsTo
    {
        $userModel = config('security.auth.user_model', 'App\\Models\\User');
        return $this->belongsTo($userModel);
    }

    public function incident(): BelongsTo
    {
        return $this->belongsTo(Incident::class);
    }

    /** Canonical string the hash chain is computed over. */
    public static function canonical(array $a): string
    {
        return json_encode([
            $a['occurred_at'] instanceof \DateTimeInterface ? $a['occurred_at']->format('Y-m-d H:i:s') : (string) $a['occurred_at'],
            $a['type'], $a['severity'], $a['source_ip'] ?? null, $a['user_id'] ?? null, $a['method'] ?? null,
            $a['route'] ?? null, $a['path'] ?? null, $a['reason'], $a['action'],
            is_array($a['context'] ?? null) ? $a['context'] : json_decode((string) ($a['context'] ?? 'null'), true),
            $a['fingerprint'],
        ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    public function severityBadge(): string
    {
        return Incident::badgeFor($this->severity);
    }
}