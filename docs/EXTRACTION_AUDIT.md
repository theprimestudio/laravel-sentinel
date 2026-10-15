# Laravel Sentinel System - Extraction Audit

## 1. Project Identification & Scope
- **Host Project**: `d:\Laragon\www\scaff12`
- **Host Environment**: PHP 8.3 / Laravel 12.x
- **Target Package Name**: `theprimestudio/laravel-sentinel`
- **Target Package Directory**: `d:\Laragon\www\laravel-sentinel-package` (sibling of host project)
- **Target Namespace**: `ThePrimeStudio\LaravelSentinel\`
- **Target Framework Compatibility**: Laravel 10.x, 11.x, and 12.x on PHP 8.2+

## 2. Repository Security Audit Findings

### 2.1 File System Antivirus & Heuristic Scanning
The repository includes an enterprise-grade file scanner located in `app/Services/Security/`:
- **`ScanEngine.php`**: Orchestrates scans across defined roots (`app`, `bootstrap`, `config`, `database`, `routes`, `resources`, `public`, `storage/app`). Employs single-host atomic locking via cache (`security:scan`), strict symlink protection (refuses to follow external links), checkpointing for deterministic resume capabilities, time budget enforcement, and memory bounding.
- **`HeuristicAnalyzer.php`**: Static rule analysis that never executes scanned files. Evaluates placement rules (e.g. server executables in upload directories), disguised PHP polyglots in media files, SSI directives (`<!--#exec`), web server config persistence (`AddHandler`, `auto_prepend_file`), and comprehensive PHP syntax inspection (dynamic code execution via `eval`/`assert`/`create_function`, OS commands via `system`/`exec`/`proc_open`/backticks, decoder chains such as `base64_decode`/`gzinflate`/`hex2bin`, long obfuscated strings, dense hex escapes, `goto` flows, and known webshell family markers).
- **`ClamAvScanner.php`**: Antivirus daemon (`clamdscan` with `--fdpass`) and CLI (`clamscan`) adapter with timeout management. Accurately reports whether engines are active and never marks files as clean if no engine ran.
- **`QuarantineService.php`**: Relocates infected or hostile files outside public web access with `0400` permissions and `.htaccess` denial, capturing comprehensive metadata (hashes, owner, group, inode, timestamps), and providing secure, audited restoration.
- **`ScannerHealth.php`**: Reports overall health status from heartbeat tracking, completed full scan age, stale run detection, ClamAV state, and configuration exposure checks (`.env`, `.git` in `public/`).

### 2.2 Content Security Review & HTML Sanitization
- **`ContentSecurityScanner.php`**: Reviews database content across multiple tables (e.g., blogs, faqs, pages, settings) for malicious markup and stored-XSS threats. Never alters data during scan.
- **`HtmlSanitizer.php`**: Pure allowlist sanitizer utilizing HTMLPurifier with `rich`, `basic`, and `plain` profiles. Features CSS property whitelisting, approved iframe hosts (YouTube, Vimeo), and multi-pass URL/entity decode attack detection.
- **`ContentBackup.php`**: Retains original raw content before sanitization is applied, enabling reversibility and auditability.

### 2.3 WAF & Request Protection Middleware
- **`DetectExploitAttempts.php`**: High-confidence regex inspection on URL paths, query parameters, and non-GET request bodies. Inspects for Path Traversal, PHP stream wrappers, null bytes, SQL Injection (`UNION SELECT`, `SLEEP`, `into outfile`, `; DROP TABLE`), Command Injection, XSS tags/handlers, and Template Injection (`{{ constructor }}`, `${jndi:`). Configurable for query blocking and body logging.
- **`BlockBots.php`**: Filters automated bots and scrapers (`curl`, `sqlmap`, `nikto`, `masscan`, `python-requests`, etc.) while safeguarding legitimate search engine crawlers (`googlebot`, `bingbot`, `duckduckbot`, etc.).
- **`SecureHeadersMiddleware.php`**: Emits robust security headers: CSP, HSTS, X-Frame-Options (`DENY`), X-Content-Type-Options (`nosniff`), Referrer-Policy, Permissions-Policy, COOP, and removes `X-Powered-By`.
- **`XSS.php`**: Supplementary recursive request input sanitizer.

### 2.4 Event Telemetry & Incident Management
- **`SecurityEventRecorder.php`**: Central telemetry gateway that redacts sensitive attributes (passwords, tokens, cookies), applies rate-limited flood control via fingerprints, groups repetitive events into incidents, and maintains a cryptographic SHA-256 hash chain (`hash = sha256(prev_hash + canonical_event)`).
- **`SecurityEvent.php` / `Incident.php` / `IncidentNote.php`**: Models managing incident tracking, assignment, status transitions, notes, and audit history.
- **`RecordAuthSecurityEvents.php`**: Event subscriber capturing failed logins, lockouts, and password resets with masked identifiers to prevent credential harvesting.
- **`SecurityIncidentNotification.php`**: Queued email notification delivering sanitized incident alerts with throttling.
- **`SecurityAuditCommand.php`**: Audits runtime configuration (`APP_KEY`, production `APP_DEBUG`, debugbar leaks, session security, file permissions on `.env` and `.git`, and prohibited dev packages in production).
- **`SecurityMonitorCommand.php`**: Periodic lightweight cron check detecting auth anomalies (brute force, credential stuffing), hash chain breakage, notification job failures, and Imunify360 status.

### 2.5 RFC 9116 security.txt
- **`SecurityTxt.php` / `SecurityTxtController.php` / `SecurityTxtAdminController.php`**: Standards-compliant security disclosure endpoint at `/.well-known/security.txt` with admin editor, validation of Contact URIs (mailto, https, tel), and expiration constraints.

### 2.6 Administration UI & Access Control
- Blade views and controllers for:
  - Security Dashboard (`SecurityDashboardController`, live polling feed, CSV export, incident management)
  - Vulnerability Management (`VulnerabilityController`, file inventory, finding resolution, quarantine management, content sanitization)
  - Security Audits (`SecurityAuditController`, audit history, check breakdowns)
  - security.txt Editor (`SecurityTxtAdminController`)
- Fine-grained Spatie permission integrations and Gate policy (`SecurityFindingPolicy`).

## 3. Extraction Strategy & Decoupling Plan
1. **Configurable Model & Table Bindings**: Host application model names (`App\Models\Blog`, `App\Models\User`, etc.) must be decoupled into package configuration (`config/security.php`).
2. **Pluggable Authorization**: When `spatie/laravel-permission` is present, it is utilized; when absent, standard Laravel Gate abilities and configurable callbacks take precedence.
3. **Packaging Standard**: Fully auto-discoverable Laravel package with publishable migrations, views, translations, and configuration.