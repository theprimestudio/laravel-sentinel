<?php

namespace ThePrimeStudio\LaravelSentinel\Models;

use Illuminate\Database\Eloquent\Model;

class SecurityAlert extends Model
{
    protected $table = 'security_alerts';

    protected $guarded = [];

    protected $casts = [
        'resolved_at' => 'datetime',
    ];
}