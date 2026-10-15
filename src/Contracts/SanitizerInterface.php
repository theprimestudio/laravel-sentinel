<?php

namespace ThePrimeStudio\LaravelSentinel\Contracts;

interface SanitizerInterface
{
    /**
     * Sanitize HTML content according to a named profile.
     */
    public function sanitize(?string $html, string $profile = 'rich'): ?string;

    /**
     * Detect dangerous patterns without modifying input.
     *
     * @return list<string>
     */
    public function detect(?string $html): array;

    /**
     * Determine if HTML contains security-sensitive patterns.
     */
    public function isDangerous(?string $html): bool;
}