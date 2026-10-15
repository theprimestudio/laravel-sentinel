<?php

namespace ThePrimeStudio\LaravelSentinel\Facades;

use Illuminate\Support\Facades\Facade;

/**
 * @method static \ThePrimeStudio\LaravelSentinel\Services\ScanEngine scanner()
 * @method static \ThePrimeStudio\LaravelSentinel\Services\HeuristicAnalyzer analyzer()
 * @method static \ThePrimeStudio\LaravelSentinel\Services\QuarantineService quarantine()
 * @method static \ThePrimeStudio\LaravelSentinel\Services\HtmlSanitizer sanitizer()
 * @method static \ThePrimeStudio\LaravelSentinel\Services\SecurityEventRecorder recorder()
 * @method static \ThePrimeStudio\LaravelSentinel\Services\ScannerHealth health()
 *
 * @see \ThePrimeStudio\LaravelSentinel\SecurityManager
 */
class Security extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return 'laravel-sentinel';
    }
}