<?php

namespace ThePrimeStudio\LaravelSentinel\Contracts;

use ThePrimeStudio\LaravelSentinel\Models\SecurityEvent;

interface EventRecorderInterface
{
    /**
     * Record a security event with automatic secrets redaction, rate limiting and hash chaining.
     *
     * @param  array<string, mixed>  $context
     */
    public function record(string $type, string $severity, string $reason, array $context = [], string $action = 'logged', ?string $sourceIp = null): ?SecurityEvent;

    /**
     * Verify recent hash chain integrity.
     *
     * @return array{ok: bool, checked: int, broken_at: ?int}
     */
    public function verifyChain(int $window = 1000): array;
}