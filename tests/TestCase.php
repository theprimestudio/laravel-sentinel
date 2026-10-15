<?php

namespace ThePrimeStudio\LaravelSentinel\Tests;

use ThePrimeStudio\LaravelSentinel\SentinelServiceProvider;
use Orchestra\Testbench\TestCase as Orchestra;

abstract class TestCase extends Orchestra
{
    protected function getPackageProviders($app): array
    {
        return [
            SentinelServiceProvider::class,
        ];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('database.default', 'testing');
        $app['config']->set('database.connections.testing', [
            'driver' => 'sqlite',
            'database' => ':memory:',
            'prefix' => '',
        ]);

        $app['config']->set('security.scanner.roots', ['app']);
        $app['config']->set('security.scanner.quarantine_path', sys_get_temp_dir().'/sec_test_quarantine');
        $app['config']->set('security.admin.permissions_enabled', false);
    }

    protected function defineEnvironmentDatabaseMigrations(): void
    {
        $this->loadMigrationsFrom(__DIR__.'/../database/migrations');
    }
}
