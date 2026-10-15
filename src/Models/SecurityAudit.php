<?php

namespace ThePrimeStudio\LaravelSentinel\Models;

use Illuminate\Database\Eloquent\Model;

class SecurityAudit extends Model
{
    protected $table = 'security_audits';

    protected $guarded = [];

    protected $casts = [
        'result_json' => 'array',
    ];
}