<?php

namespace ThePrimeStudio\LaravelSentinel\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class QuarantineItem extends Model
{
    protected $table = 'security_quarantine';

    protected $guarded = [];

    protected $casts = [
        'metadata' => 'array',
        'quarantined_at' => 'datetime',
        'restored_at' => 'datetime',
    ];

    public function finding(): BelongsTo
    {
        return $this->belongsTo(Finding::class);
    }

    public function quarantinedBy(): BelongsTo
    {
        $userModel = config('security.auth.user_model', 'App\\Models\\User');
        return $this->belongsTo($userModel, 'quarantined_by');
    }

    public function restoredBy(): BelongsTo
    {
        $userModel = config('security.auth.user_model', 'App\\Models\\User');
        return $this->belongsTo($userModel, 'restored_by');
    }

    public function isRestored(): bool
    {
        return $this->status === 'restored';
    }
}