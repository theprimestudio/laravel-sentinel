<?php

namespace ThePrimeStudio\LaravelSentinel\Console;

use ThePrimeStudio\LaravelSentinel\Models\SecurityAudit;
use ThePrimeStudio\LaravelSentinel\Models\SecurityAlert;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Schema;

class SecurityAuditCommand extends Command
{
    protected $signature = 'security:audit';

    protected $description = 'Run a security audit for the application';

    public function handle()
    {
        $critical = [];
        $warnings = [];
        $passed = [];

        $isProduction = app()->environment('production');

        if (config('app.key')) {
            $passed[] = 'APP_KEY is set.';
        } else {
            $critical[] = 'APP_KEY is missing!';
        }

        if ($isProduction && config('app.debug')) {
            $critical[] = 'APP_DEBUG is enabled in production!';
        } else {
            $passed[] = 'APP_DEBUG configuration is safe.';
        }

        if ($isProduction && config('debugbar.enabled')) {
            $critical[] = 'Debugbar is enabled in production!';
        } else {
            $passed[] = 'Debugbar configuration is safe.';
        }

        if ($isProduction && !config('session.secure')) {
            $warnings[] = 'Session cookies are not set to secure!';
        } else {
            $passed[] = 'Session cookie security is safe.';
        }

        $sensitiveFiles = ['.env', '.git'];

        foreach ($sensitiveFiles as $file) {
            $path = base_path($file);

            if (File::exists($path)) {
                $perms = fileperms($path);

                if (($perms & 0777) === 0777) {
                    $critical[] = "Sensitive file {$file} has 777 permissions!";
                } else {
                    $passed[] = "Sensitive file {$file} permissions are safe.";
                }
            }
        }

        if ($isProduction) {
            $devPackages = [
                'barryvdh/laravel-debugbar',
                'phpunit/phpunit',
                'pestphp/pest',
                'fakerphp/faker',
                'laravel/pint',
                'mockery/mockery',
            ];

            $installedJsonPath = base_path('vendor/composer/installed.json');
            $hasDevPackages = false;

            if (File::exists($installedJsonPath)) {
                $installed = json_decode(File::get($installedJsonPath), true);
                $packages = $installed['packages'] ?? [];
                $packageNames = array_column($packages, 'name');

                foreach ($devPackages as $devPackage) {
                    if (in_array($devPackage, $packageNames, true)) {
                        $critical[] = "Dev package {$devPackage} is installed on production!";
                        $hasDevPackages = true;
                    }
                }
            }

            if (!$hasDevPackages) {
                $passed[] = 'No prohibited dev packages found on production.';
            }
        }

        $this->info('SECURITY AUDIT REPORT');
        $this->info('=====================');

        $this->error('Critical:');

        foreach ($critical as $issue) {
            $this->line(" - [X] {$issue}");
        }

        $this->warn('Warnings:');

        foreach ($warnings as $issue) {
            $this->line(" - [!] {$issue}");
        }

        $this->info('Passed:');

        foreach ($passed as $issue) {
            $this->line(" - [v] {$issue}");
        }

        $score = 100 - (count($critical) * 20) - (count($warnings) * 5);
        $score = max(0, $score);

        $status = count($critical) > 0
            ? 'Failed'
            : (count($warnings) > 0 ? 'Warning' : 'Passed');

        /*
         * Validate audit model/table before database logging.
         */
        $audit = null;

        if (
            class_exists(SecurityAudit::class) &&
            Schema::hasTable((new SecurityAudit)->getTable())
        ) {
            try {
                $audit = SecurityAudit::create([
                    'environment' => app()->environment(),
                    'status' => $status,
                    'score' => $score,
                    'result_json' => json_encode([
                        'critical' => $critical,
                        'warnings' => $warnings,
                        'passed' => $passed,
                    ]),
                ]);
            } catch (\Throwable $e) {
                $this->warn('Security audit could not be saved: ' . $e->getMessage());
            }
        } else {
            $this->warn('SecurityAudit model or table is not available. Database logging skipped.');
        }

        /*
         * Create alert only when the alert model/table exists.
         */
        if (count($critical) > 0) {
            $auditId = $audit?->id;

            $message = 'Critical security issues found during audit';

            if ($auditId) {
                $message .= " (#{$auditId})";
            }

            $message .= ":\n" . implode("\n", $critical);

            if (
                class_exists(SecurityAlert::class) &&
                Schema::hasTable((new SecurityAlert)->getTable())
            ) {
                try {
                    SecurityAlert::create([
                        'severity' => 'critical',
                        'title' => 'Critical Security Issues Found',
                        'description' => $message,
                    ]);
                } catch (\Throwable $e) {
                    $this->warn('Security alert could not be saved: ' . $e->getMessage());
                }
            } else {
                $this->warn('SecurityAlert model or table is not available. Alert logging skipped.');
            }

            try {
                Mail::raw($message, function ($mail) {
                    $to = config('security.notifications.mail_to');
                if (!empty($to)) {
                    $mail->to(array_filter(array_map('trim', explode(',', $to))))
                        ->subject('CRITICAL: Security Audit Failed');
                }
                });
            } catch (\Throwable $e) {
                $this->error('Failed to send alert email: ' . $e->getMessage());
            }

            if ($isProduction) {
                return self::FAILURE;
            }
        }

        return self::SUCCESS;
    }
}
