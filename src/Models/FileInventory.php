<?php

namespace ThePrimeStudio\LaravelSentinel\Models;

use Illuminate\Database\Eloquent\Model;

class FileInventory extends Model
{
    protected $table = 'security_file_inventory';

    protected $guarded = [];

    protected $casts = [
        'is_critical' => 'boolean',
        'first_seen_at' => 'datetime',
        'last_seen_at' => 'datetime',
        'last_scanned_at' => 'datetime',
        'missing_since' => 'datetime',
    ];
}