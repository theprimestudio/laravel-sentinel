<?php

namespace ThePrimeStudio\LaravelSentinel;

use Illuminate\Routing\Router;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\ServiceProvider;
use ThePrimeStudio\LaravelSentinel\Console\SecurityAuditCommand;
use ThePrimeStudio\LaravelSentinel\Console\SecurityMonitorCommand;
use ThePrimeStudio\LaravelSentinel\Console\SecurityScanCommand;
use ThePrimeStudio\LaravelSentinel\Console\SecurityScanContentCommand;
use ThePrimeStudio\LaravelSentinel\Contracts\EventRecorderInterface;
use ThePrimeStudio\LaravelSentinel\Contracts\QuarantineInterface;
use ThePrimeStudio\LaravelSentinel\Contracts\SanitizerInterface;
use ThePrimeStudio\LaravelSentinel\Contracts\ScannerInterface;
use ThePrimeStudio\LaravelSentinel\Http\Middleware\BlockBots;
use ThePrimeStudio\LaravelSentinel\Http\Middleware\DetectExploitAttempts;
use ThePrimeStudio\LaravelSentinel\Http\Middleware\SecureHeadersMiddleware;
use ThePrimeStudio\LaravelSentinel\Http\Middleware\XSS;
use ThePrimeStudio\LaravelSentinel\Listeners\RecordAuthSecurityEvents;
use ThePrimeStudio\LaravelSentinel\Models\Finding;
use ThePrimeStudio\LaravelSentinel\Policies\SecurityFindingPolicy;
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

class SentinelServiceProvider extends ServiceProvider
{
    /**
     * Register any package services.
     */
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/security.php', 'security');

        // Core singletons & aliases
        $this->app->singleton('laravel-sentinel', fn ($app) => new SecurityManager($app));
        $this->app->alias('laravel-sentinel', 'laravel-security');

        $this->app->singleton(ClamAvScanner::class);
        $this->app->singleton(HeuristicAnalyzer::class);
        $this->app->singleton(ScannerHealth::class);
        $this->app->singleton(RequestContextService::class);
        $this->app->singleton(FileSecurityService::class);

        // Bind interfaces to implementations
        $this->app->singleton(HtmlSanitizer::class);
        $this->app->bind(SanitizerInterface::class, HtmlSanitizer::class);

        $this->app->singleton(QuarantineService::class);
        $this->app->bind(QuarantineInterface::class, QuarantineService::class);

        $this->app->singleton(SecurityEventRecorder::class);
        $this->app->bind(EventRecorderInterface::class, SecurityEventRecorder::class);

        $this->app->singleton(ScanEngine::class);
        $this->app->bind(ScannerInterface::class, ScanEngine::class);

        $this->app->singleton(ContentSecurityScanner::class);
    }

    /**
     * Bootstrap any package services.
     */
    public function boot(): void
    {
        $this->registerPublishing();
        $this->registerResources();
        $this->registerCommands();
        $this->registerMiddleware();
        $this->registerListeners();
        $this->registerPolicies();
    }

    protected function registerPublishing(): void
    {
        if ($this->app->runningInConsole()) {
            // Configuration (published as config/security.php)
            $this->publishes([
                __DIR__.'/../config/security.php' => config_path('security.php'),
            ], ['sentinel-config', 'security-config']);

            // Migrations
            $this->publishes([
                __DIR__.'/../database/migrations' => database_path('migrations'),
            ], ['sentinel-migrations', 'security-migrations']);

            // Views
            $this->publishes([
                __DIR__.'/../resources/views' => resource_path('views/vendor/laravel-sentinel'),
            ], ['sentinel-views', 'security-views']);

            // All package assets combined
            $this->publishes([
                __DIR__.'/../config/security.php' => config_path('security.php'),
                __DIR__.'/../database/migrations' => database_path('migrations'),
                __DIR__.'/../resources/views' => resource_path('views/vendor/laravel-sentinel'),
            ], 'sentinel');
        }
    }

    protected function registerResources(): void
    {
        $this->loadMigrationsFrom(__DIR__.'/../database/migrations');
        $this->loadViewsFrom(__DIR__.'/../resources/views', 'laravel-sentinel');
        $this->loadRoutesFrom(__DIR__.'/../routes/web.php');
    }

    protected function registerCommands(): void
    {
        if ($this->app->runningInConsole()) {
            $this->commands([
                SecurityScanCommand::class,
                SecurityScanContentCommand::class,
                SecurityAuditCommand::class,
                SecurityMonitorCommand::class,
            ]);
        }
    }

    protected function registerMiddleware(): void
    {
        /** @var Router $router */
        $router = $this->app->make(Router::class);

        $router->aliasMiddleware('security.headers', SecureHeadersMiddleware::class);
        $router->aliasMiddleware('security.waf', DetectExploitAttempts::class);
        $router->aliasMiddleware('security.bots', BlockBots::class);
        $router->aliasMiddleware('security.xss', XSS::class);

        // Sentinel aliases
        $router->aliasMiddleware('sentinel.headers', SecureHeadersMiddleware::class);
        $router->aliasMiddleware('sentinel.waf', DetectExploitAttempts::class);
        $router->aliasMiddleware('sentinel.bots', BlockBots::class);
        $router->aliasMiddleware('sentinel.xss', XSS::class);
    }

    protected function registerListeners(): void
    {
        Event::subscribe(RecordAuthSecurityEvents::class);
    }

    protected function registerPolicies(): void
    {
        Gate::policy(Finding::class, SecurityFindingPolicy::class);
    }
}
