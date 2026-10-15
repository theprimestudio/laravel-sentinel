<?php

namespace ThePrimeStudio\LaravelSentinel\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class FindingEvent extends Model
{
    protected $table = 'security_finding_events';

    protected $guarded = [];

    protected $casts = [
        'meta' => 'array',
    ];

    public function finding(): BelongsTo
    {
        return $this->belongsTo(Finding::class);
    }

    public function user(): BelongsTo
    {
        $userModel = config('security.auth.user_model', 'App\\Models\\User');
        return $this->belongsTo($userModel);
    }
}