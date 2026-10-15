<?php

namespace ThePrimeStudio\LaravelSentinel;

use ThePrimeStudio\LaravelSentinel\Services\ClamAvScanner;
use ThePrimeStudio\LaravelSentinel\Services\ContentSecurityScanner;
use ThePrimeStudio\LaravelSentinel\Services\FileSecurityService;
use ThePrimeStudio\LaravelSentinel\Services\HeuristicAnalyzer;
use ThePrimeStudio\LaravelSentinel\Services\HtmlSanitizer;
use ThePrimeStudio\LaravelSentinel\Services\QuarantineService;
use ThePrimeStudio\LaravelSentinel\Services\RequestContextService;
use ThePrimeStudio\LaravelSentinel\Services\ScanEngine;
use ThePrimeStudio\LaravelSentinel\Services\ScannerHealth;
use ThePrimeStudio\LaravelSentinel\Services\SecurityEventRecorder;
use Illuminate\Contracts\Foundation\Application;

class SecurityManager
{
    public function __construct(protected Application $app) {}

    public function scanner(): ScanEngine
    {
        return $this->app->make(ScanEngine::class);
    }

    public function analyzer(): HeuristicAnalyzer
    {
        return $this->app->make(HeuristicAnalyzer::class);
    }

    public function clamav(): ClamAvScanner
    {
        return $this->app->make(ClamAvScanner::class);
    }

    public function quarantine(): QuarantineService
    {
        return $this->app->make(QuarantineService::class);
    }

    public function health(): ScannerHealth
    {
        return $this->app->make(ScannerHealth::class);
    }

    public function content(): ContentSecurityScanner
    {
        return $this->app->make(ContentSecurityScanner::class);
    }

    public function sanitizer(): HtmlSanitizer
    {
        return $this->app->make(HtmlSanitizer::class);
    }

    public function recorder(): SecurityEventRecorder
    {
        return $this->app->make(SecurityEventRecorder::class);
    }

    public function fileSecurity(): FileSecurityService
    {
        return $this->app->make(FileSecurityService::class);
    }

    public function context(): RequestContextService
    {
        return $this->app->make(RequestContextService::class);
    }
}