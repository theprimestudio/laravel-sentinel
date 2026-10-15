<?php

namespace ThePrimeStudio\LaravelSentinel\Contracts;

use ThePrimeStudio\LaravelSentinel\Models\ScanRun;

interface ScannerInterface
{
    /**
     * Run a security scan with options.
     *
     * @param  array<string, mixed>  $options
     */
    public function run(array $options = []): ScanRun;

    /**
     * Get reported findings from the last executed run.
     *
     * @return list<array<string, mixed>>
     */
    public function reported(): array;
}