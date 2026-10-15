<?php

namespace ThePrimeStudio\LaravelSentinel\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class ContentBackup extends Model
{
    protected $table = 'security_content_backups';

    protected $guarded = [];

    protected $casts = [
        'applied_at' => 'datetime',
        'restored_at' => 'datetime',
    ];

    public function finding(): BelongsTo
    {
        return $this->belongsTo(Finding::class);
    }

    public function appliedBy(): BelongsTo
    {
        $userModel = config('security.auth.user_model', 'App\\Models\\User');
        return $this->belongsTo($userModel, 'applied_by');
    }

    public function restoredBy(): BelongsTo
    {
        $userModel = config('security.auth.user_model', 'App\\Models\\User');
        return $this->belongsTo($userModel, 'restored_by');
    }
}