<?php

namespace ThePrimeStudio\LaravelSentinel\Contracts;

use ThePrimeStudio\LaravelSentinel\Models\Finding;
use ThePrimeStudio\LaravelSentinel\Models\QuarantineItem;

interface QuarantineInterface
{
    /**
     * Relocate a finding's target file into isolated quarantine storage.
     */
    public function quarantine(Finding $finding, ?object $user = null, string $reason = 'manual', ?string $ip = null): QuarantineItem;

    /**
     * Restore a quarantined item back to its original target path.
     */
    public function restore(QuarantineItem $item, ?object $user = null, ?string $note = null, ?string $ip = null): void;

    /**
     * Return the quarantine root directory path.
     */
    public function root(): string;
}