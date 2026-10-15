# Changelog

All notable changes to `theprimestudio/laravel-sentinel` will be documented in this file.

## 1.0.0 - 2026-10-16

### Initial Release
- Extracted comprehensive security, antivirus, and incident management suite from production Laravel application.
- High-performance, checkpointed file scanner (`ScanEngine`) with SHA-256 baselines and atomic locking.
- Static heuristic code analyzer (`HeuristicAnalyzer`) for webshells, obfuscation decoder chains, and suspicious PHP polyglots.
- Dual-mode ClamAV adapter (`ClamAvScanner`) supporting `clamdscan` daemon with `--fdpass` and `clamscan` fallback.
- Forensic quarantine service (`QuarantineService`) with metadata capture and auditable restoration.
- Database content security reviewer (`ContentSecurityScanner`) with HTMLPurifier allowlist sanitizer (`HtmlSanitizer`) and reversible backups (`ContentBackup`).
- WAF request protection middleware:
  - `DetectExploitAttempts`: inspects URL paths, query parameters, and non-GET request bodies.
  - `BlockBots`: mitigates automated bots and scrapers while protecting legitimate search engines.
  - `SecureHeadersMiddleware`: enforces CSP, HSTS, X-Frame-Options, and removes `X-Powered-By`.
  - `XSS`: recursive request input sanitization.
- Tamper-evident incident telemetry (`SecurityEventRecorder`) utilizing cryptographic SHA-256 hash chaining.
- RFC 9116 `security.txt` support with administrative editor and public endpoint.
- Artisan commands:
  - `php artisan security:scan`
  - `php artisan security:scan-content`
  - `php artisan security:audit`
  - `php artisan security:monitor`
- Complete administrative Blade UI for findings, quarantine management, live incident feed, and audits.
- Full compatibility with Laravel 10.x, 11.x, and 12.x on PHP 8.2+.