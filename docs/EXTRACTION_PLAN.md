# Laravel Sentinel Package - Extraction & Implementation Plan

## Phase 1: Audit & Documentation (Completed)
- [x] Comprehensive code audit of `scaff12`.
- [x] Create `docs/EXTRACTION_AUDIT.md`.
- [x] Create `docs/COMPONENT_INVENTORY.md`.
- [x] Create `docs/DEPENDENCY_MAP.md`.
- [x] Create `docs/EXTRACTION_PLAN.md`.

## Phase 2: Package Architecture & Composer Initialization
- [ ] Initialize `composer.json` for `theprimestudio/laravel-sentinel`:
  - PHP: `^8.2`
  - Laravel Framework: `^10.0 || ^11.0 || ^12.0`
  - HTMLPurifier: `^4.17 || ^4.18`
  - Dev dependencies: `orchestra/testbench`, `phpunit/phpunit`, `pestphp/pest`.
  - Auto-discovery for `ThePrimeStudio\LaravelSentinel\SentinelServiceProvider`.
- [ ] Establish package directory structure:
  - `src/` (Console, Contracts, Events, Http, Listeners, Models, Notifications, Policies, Services, Support)
  - `config/` (`security.php`)
  - `database/migrations/`
  - `resources/views/`
  - `routes/`
  - `tests/`
- [ ] Create project quality files (`phpunit.xml`, `phpstan.neon`, `.editorconfig`, `LICENSE`, `README.md`, `CHANGELOG.md`).

## Phase 3: Core Logic Extraction & Adapter Refactoring
- [ ] Extract `HeuristicAnalyzer`: Port all detection rules, scoring, and webshell signatures.
- [ ] Extract `ClamAvScanner`: Port process execution, clamdscan/clamscan detection, and timeout handling.
- [ ] Extract `QuarantineService`: Port secure file quarantine, metadata tracking, and restoration.
- [ ] Extract `ScanEngine`: Port walk traversal, checkpointing, time budget, and inventory sync.
- [ ] Extract `HtmlSanitizer`: Port HTMLPurifier configuration, profiles, and attack detection.
- [ ] Extract `ContentSecurityScanner`: Decouple model mappings into configurable content sources.
- [ ] Extract `SecurityEventRecorder`: Port telemetry, incident aggregation, flood rate limiting, and SHA-256 hash chaining.
- [ ] Extract `FileSecurityService` & `RequestContextService`.
- [ ] Port Models (`ScanRun`, `FileInventory`, `Finding`, `FindingEvent`, `QuarantineItem`, `SecurityEvent`, `Incident`, `IncidentNote`, `ContentBackup`, `SecurityTxt`, `SecurityAlert`, `SecurityAudit`).

## Phase 4: WAF Middleware, Events & Console Commands
- [ ] Extract Middleware (`DetectExploitAttempts`, `BlockBots`, `SecureHeadersMiddleware`, `XSS`).
- [ ] Extract Event Subscriber (`RecordAuthSecurityEvents`).
- [ ] Extract Notification (`SecurityIncidentNotification`).
- [ ] Extract Artisan Commands (`SecurityScanCommand`, `SecurityScanContentCommand`, `SecurityAuditCommand`, `SecurityMonitorCommand`).
- [ ] Port Policy (`SecurityFindingPolicy`).

## Phase 5: Administration UI, Routes & Migrations
- [ ] Extract Controllers (`SecurityDashboardController`, `VulnerabilityController`, `SecurityTxtController`, `SecurityTxtAdminController`, `SecurityAuditController`).
- [ ] Extract Blade Views into `resources/views/`.
- [ ] Extract Routes (`routes/web.php` and `routes/api.php` if needed).
- [ ] Extract Migrations into `database/migrations/`.

## Phase 6: Service Provider & Configuration
- [ ] Build `SecurityServiceProvider`:
  - Config publishing
  - Migration loading and publishing
  - Route loading with configurable prefix and middleware
  - View loading and publishing
  - Command registration
  - Singleton and interface bindings
  - Event subscriber registration
- [ ] Finalize `config/security.php` with safe, production-grade defaults.

## Phase 7: Automated Testing & Validation
- [ ] Build unit and feature test suite using Orchestra Testbench.
- [ ] Verify test suite passes with `phpunit` or `pest`.
- [ ] Validate path-repository installation readiness.

## Phase 8: Documentation & Packagist Readiness
- [ ] Write complete `README.md` with installation, configuration, command reference, and security best practices.
- [ ] Write `CONTRIBUTING.md`, `CHANGELOG.md`, `LICENSE` (MIT).
- [ ] Verify original application `scaff12` remains completely intact and undisturbed.