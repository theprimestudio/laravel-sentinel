<?php

use ThePrimeStudio\LaravelSentinel\Http\Controllers\SecurityAuditController;
use ThePrimeStudio\LaravelSentinel\Http\Controllers\SecurityDashboardController;
use ThePrimeStudio\LaravelSentinel\Http\Controllers\SecurityTxtAdminController;
use ThePrimeStudio\LaravelSentinel\Http\Controllers\SecurityTxtController;
use ThePrimeStudio\LaravelSentinel\Http\Controllers\VulnerabilityController;
use Illuminate\Support\Facades\Route;

// Public RFC 9116 security.txt route
Route::get('/.well-known/security.txt', [SecurityTxtController::class, 'show'])
    ->name('security-txt.show');

// Admin panel routes (configurable prefix, middleware, and route name prefix)
if (config('security.admin.enabled', true)) {
    Route::prefix(config('security.admin.prefix', 'admin'))
        ->middleware(config('security.admin.middleware', ['web', 'auth']))
        ->as(config('security.admin.route_name_prefix', 'admin.'))
        ->group(function () {
            // Vulnerabilities (file scanner findings, quarantine, scanner health)
            Route::get('vulnerabilities', [VulnerabilityController::class, 'index'])->name('vulnerabilities.index');
            Route::get('vulnerabilities/alerts', [VulnerabilityController::class, 'alerts'])->middleware('throttle:30,1')->name('vulnerabilities.alerts');
            Route::get('vulnerabilities/{finding}', [VulnerabilityController::class, 'show'])->whereNumber('finding')->name('vulnerabilities.show');
            Route::post('vulnerabilities/{finding}/status', [VulnerabilityController::class, 'updateStatus'])->whereNumber('finding')->name('vulnerabilities.status');
            Route::post('vulnerabilities/{finding}/quarantine', [VulnerabilityController::class, 'quarantine'])->whereNumber('finding')->name('vulnerabilities.quarantine');
            Route::post('vulnerabilities/{finding}/accept-baseline', [VulnerabilityController::class, 'acceptBaseline'])->whereNumber('finding')->name('vulnerabilities.accept-baseline');
            Route::post('vulnerabilities/quarantine/{item}/restore', [VulnerabilityController::class, 'restore'])->whereNumber('item')->name('vulnerabilities.restore');

            Route::post('vulnerabilities/{finding}/content/apply', [VulnerabilityController::class, 'applyContentSanitize'])->whereNumber('finding')->name('vulnerabilities.content.apply');
            Route::post('vulnerabilities/content-backups/{backup}/restore', [VulnerabilityController::class, 'restoreContent'])->whereNumber('backup')->name('vulnerabilities.content.restore');

            // Security dashboard & incidents
            Route::get('security-dashboard', [SecurityDashboardController::class, 'index'])->name('security-dashboard.index');
            Route::get('security-dashboard/feed', [SecurityDashboardController::class, 'feed'])->middleware('throttle:60,1')->name('security-dashboard.feed');
            Route::get('security-dashboard/export', [SecurityDashboardController::class, 'export'])->middleware('throttle:10,1')->name('security-dashboard.export');
            Route::get('security-dashboard/incidents/{incident}', [SecurityDashboardController::class, 'incident'])->whereNumber('incident')->name('security-dashboard.incident');
            Route::post('security-dashboard/incidents/{incident}', [SecurityDashboardController::class, 'updateIncident'])->whereNumber('incident')->name('security-dashboard.incident.update');

            // security.txt (RFC 9116)
            Route::get('security-txt', [SecurityTxtAdminController::class, 'edit'])->name('security-txt.edit');
            Route::put('security-txt', [SecurityTxtAdminController::class, 'update'])->name('security-txt.update');

            // Security Audits
            Route::get('security-audits', [SecurityAuditController::class, 'index'])->name('security-audits.index');
            Route::get('security-audits/{id}', [SecurityAuditController::class, 'show'])->name('security-audits.show');
        });
}