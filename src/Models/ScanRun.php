<?php

namespace ThePrimeStudio\LaravelSentinel\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;

class ScanRun extends Model
{
    protected $table = 'security_scan_runs';

    protected $guarded = [];

    protected $attributes = [
        'files_seen' => 0,
        'files_scanned' => 0,
        'files_changed' => 0,
        'files_deleted' => 0,
        'findings_count' => 0,
        'errors_count' => 0,
    ];

    protected $casts = [
        'dry_run' => 'boolean',
        'engines' => 'array',
        'coverage_gaps' => 'array',
        'roots' => 'array',
        'started_at' => 'datetime',
        'finished_at' => 'datetime',
    ];

    public function findings(): HasMany
    {
        return $this->hasMany(Finding::class, 'scan_run_id');
    }

    /** A run only counts as "clean" if it completed, had no errors and no coverage gaps. */
    public function isTrustworthy(): bool
    {
        return $this->status === 'completed' && $this->errors_count === 0;
    }
}