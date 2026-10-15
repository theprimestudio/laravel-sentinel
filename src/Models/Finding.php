<?php

namespace ThePrimeStudio\LaravelSentinel\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Relations\HasOne;

class Finding extends Model
{
    public const SEVERITIES = ['critical', 'high', 'medium', 'low'];

    public const OPEN_STATUSES = ['open', 'acknowledged'];

    protected $table = 'security_findings';

    protected $guarded = [];

    protected $casts = [
        'reasons' => 'array',
        'first_detected_at' => 'datetime',
        'last_detected_at' => 'datetime',
        'resolved_at' => 'datetime',
    ];

    public function scopeUnresolved(Builder $query): Builder
    {
        return $query->whereIn('status', self::OPEN_STATUSES);
    }

    public function scanRun(): BelongsTo
    {
        return $this->belongsTo(ScanRun::class, 'scan_run_id');
    }

    public function resolver(): BelongsTo
    {
        $userModel = config('security.auth.user_model', 'App\\Models\\User');
        return $this->belongsTo($userModel, 'resolved_by');
    }

    public function events(): HasMany
    {
        return $this->hasMany(FindingEvent::class)->latest('id');
    }

    public function quarantine(): HasOne
    {
        return $this->hasOne(QuarantineItem::class)->latestOfMany();
    }

    /**
     * How the finding was established.
     */
    public function detectionBasis(): string
    {
        return match (true) {
            str_starts_with($this->rule, 'clamav.') => 'Confirmed by ClamAV signature',
            str_starts_with($this->rule, 'imunify.') => 'Confirmed by Imunify360 signature',
            $this->category === 'integrity' => 'Integrity change (needs verification against deployment)',
            str_starts_with($this->path, 'db://') => 'Stored-content check (needs review)',
            default => 'Heuristic — suspected, not confirmed malware',
        };
    }

    public function severityBadge(): string
    {
        return match ($this->severity) {
            'critical' => 'badge bg-danger',
            'high' => 'badge bg-warning text-dark',
            'medium' => 'badge bg-info text-dark',
            default => 'badge bg-secondary',
        };
    }

    public function statusBadge(): string
    {
        return match ($this->status) {
            'open' => 'badge bg-danger',
            'acknowledged' => 'badge bg-warning text-dark',
            'quarantined' => 'badge bg-primary',
            'resolved' => 'badge bg-success',
            'false_positive' => 'badge bg-secondary',
            default => 'badge bg-light text-dark',
        };
    }
}