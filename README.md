# Laravel Sentinel

[![Latest Version on Packagist](https://img.shields.io/packagist/v/theprimestudio/laravel-sentinel.svg?style=flat-square)](https://packagist.org/packages/theprimestudio/laravel-sentinel)
[![Total Downloads](https://img.shields.io/packagist/dt/theprimestudio/laravel-sentinel.svg?style=flat-square)](https://packagist.org/packages/theprimestudio/laravel-sentinel)
[![License](https://img.shields.io/packagist/l/theprimestudio/laravel-sentinel.svg?style=flat-square)](https://packagist.org/packages/theprimestudio/laravel-sentinel)

Enterprise-grade security, antivirus, webshell detection, Web Application Firewall (WAF), file integrity monitoring, forensic quarantine, and tamper-evident telemetry for Laravel 10, 11, and 12.

---

## Key Features

1. **Deterministic File Integrity & Antivirus Scanner**
   - **Static Heuristic Code Analyzer**: Pure static analysis identifying web shells, disguised PHP polyglots in image files, SSI directives, server configuration overrides (`.htaccess` / `.user.ini`), dynamic evaluations (`eval`/`assert`), system command executions, and multi-layer decoder chains without executing target files.
   - **ClamAV Integration**: Automatic detection and integration with local `clamdscan` daemons (utilizing `--fdpass` for zero-overhead permissions) and fallback to standalone `clamscan`.
   - **Baseline Inventory**: SHA-256 state tracking differentiating authorized deployments (`--accept-baseline`) from hostile file tampering.
   - **Atomic Scanning Engine**: Checkpointing, memory-bounded file traversal, time budgeting, and crash-resilient resume functionality.

2. **Forensic Quarantine**
   - Moves detected threats out of public web root into dated quarantine directories.
   - Enforces restrictive `0400` permissions with Apache/nginx execution denial.
   - Retains comprehensive metadata (SHA-256, owner UID, group GID, inode, timestamps, host) with authorized, auditable restoration.

3. **Database Content Security Review**
   - Scans database tables for stored-XSS and injected markup.
   - HTMLPurifier-backed sanitizer with `rich`, `basic`, and `plain` profiles.
   - Multi-pass URL and entity decode attack detection.
   - Reversible backups (`security_content_backups`) before applying sanitization, allowing CLI or UI rollback.

4. **Web Application Firewall (WAF) & Request Defense**
   - Inspects URL paths, query parameters, and non-GET request bodies for Path Traversal, PHP stream wrappers, null bytes, SQL Injection, Command Injection, XSS, and Template Injection.
   - Automated bot mitigation filtering automated attack tools while safeguarding legitimate search engines.
   - HTTP Security Headers: Content Security Policy (CSP), HSTS, X-Frame-Options (`DENY`), X-Content-Type-Options (`nosniff`), Referrer-Policy, and `X-Powered-By` suppression.

5. **Tamper-Evident Incident Management & Telemetry**
   - Cryptographic SHA-256 hash chaining (`hash = sha256(prev_hash + canonical_event)`) ensuring stored audit logs cannot be edited or deleted without detection.
   - Automated incident clustering with rate-limited flood suppression.
   - Authentication anomaly detection: Brute-force and credential-stuffing monitoring with identifier masking.
   - Throttled queued email notifications for critical incidents.

6. **RFC 9116 security.txt**
   - Standards-compliant security disclosure policy at `/.well-known/security.txt`.
   - Administrative GUI editor with URI validation and expiry constraints.

7. **Full Administration UI**
   - Complete Blade administration panel for Vulnerabilities, File Findings, Quarantine Review, Incident Feed with real-time polling, CSV Export, and Security Audits.

---

## Installation

You can install the package via Composer:

```bash
composer require theprimestudio/laravel-sentinel
```

Publish configuration, migrations, and views:

```bash
php artisan vendor:publish --provider="ThePrimeStudio\LaravelSentinel\SentinelServiceProvider"
```

Or publish individual assets via tags:

```bash
php artisan vendor:publish --tag="sentinel-config"
php artisan vendor:publish --tag="sentinel-migrations"
php artisan vendor:publish --tag="sentinel-views"
```

Run the database migrations:

```bash
php artisan migrate
```

---

## Configuration

Edit `config/security.php` to customize your security policies:

- **`enabled`**: Master toggle for all security features.
- **`auth.user_model`**: Host application user model (defaults to `App\Models\User`).
- **`admin`**: Configure route prefix (`admin`), route name prefix (`admin.`), middleware (`['web', 'auth']`), and permission integration.
- **`csp`**: Content Security Policy directives.
- **`scanner`**: Roots to scan, excluded paths, quarantine path, and ClamAV settings.
- **`exploit_protection`**: WAF query and body inspection modes (`block` vs. `log`).

---

## Console Commands

```bash
# Run incremental file security scan
php artisan security:scan --mode=incremental

# Run full baseline scan
php artisan security:scan --mode=full

# Accept current files as trusted deployment baseline
php artisan security:scan --accept-baseline

# Watch filesystem for real-time changes
php artisan security:scan --mode=watch

# Review stored database content for XSS
php artisan security:scan-content

# Run application security audit
php artisan security:audit

# Run periodic background security monitoring
php artisan security:monitor
```

---

## Scheduling & Daemon Setup

In Laravel 11 & 12, register scheduled tasks in `routes/console.php`:

```php
use Illuminate\Support\Facades\Schedule;

Schedule::command('security:scan --mode=incremental')->everyFifteenMinutes()->withoutOverlapping(60)->runInBackground();
Schedule::command('security:scan --mode=full --resume')->dailyAt('03:15')->withoutOverlapping(240)->runInBackground();
Schedule::command('security:monitor')->everyFiveMinutes()->withoutOverlapping(10)->runInBackground();
Schedule::command('security:scan-content')->dailyAt('03:45')->withoutOverlapping(120)->runInBackground();
Schedule::command('security:audit')->daily();
```

---

## Credits

**Laravel Sentinel** is proudly built and maintained by **[The Prime Studio](https://theprimestudio.com)**.

---

## License

The MIT License (MIT). Please see [License File](LICENSE) for more information.