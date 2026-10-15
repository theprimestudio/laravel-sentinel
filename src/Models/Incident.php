<?php

namespace ThePrimeStudio\LaravelSentinel\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

class Incident extends Model
{
    public const STATUSES = ['open', 'acknowledged', 'investigating', 'resolved', 'false_positive'];

    public const OPEN_STATUSES = ['open', 'acknowledged', 'investigating'];

    public const SEVERITY_RANK = ['low' => 1, 'medium' => 2, 'high' => 3, 'critical' => 4];

    protected $table = 'security_incidents';

    protected $guarded = [];

    protected $casts = [
        'first_seen_at' => 'datetime',
        'last_seen_at' => 'datetime',
        'notified_at' => 'datetime',
        'resolved_at' => 'datetime',
    ];

    public function scopeUnresolved(Builder $q): Builder
    {
        return $q->whereIn('status', self::OPEN_STATUSES);
    }

    public function events(): HasMany
    {
        return $this->hasMany(SecurityEvent::class)->latest('id');
    }

    public function notes(): HasMany
    {
        return $this->hasMany(IncidentNote::class)->latest('id');
    }

    public function assignee(): BelongsTo
    {
        $userModel = config('security.auth.user_model', 'App\\Models\\User');
        return $this->belongsTo($userModel, 'assigned_to');
    }

    public function resolver(): BelongsTo
    {
        $userModel = config('security.auth.user_model', 'App\\Models\\User');
        return $this->belongsTo($userModel, 'resolved_by');
    }

    public static function badgeFor(?string $severity): string
    {
        return match ($severity) {
            'critical' => 'bg-danger',
            'high' => 'bg-warning text-dark',
            'medium' => 'bg-info text-dark',
            default => 'bg-secondary',
        };
    }
}