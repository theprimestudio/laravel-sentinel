<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Master Enable Switch
    |--------------------------------------------------------------------------
    |
    | Globally toggles the security features. When disabled, middleware and
    | background monitoring pass through without active blocking or auditing.
    |
    */
    'enabled' => env('SECURITY_ENABLED', true),

    /*
    |--------------------------------------------------------------------------
    | Authentication & User Model Integration
    |--------------------------------------------------------------------------
    |
    | Defines how the package associates audit logs, findings, and quarantine
    | actions with the host application's user model and authentication guard.
    |
    */
    'auth' => [
        'user_model' => env('SECURITY_USER_MODEL', 'App\\Models\\User'),
        'guard' => env('SECURITY_AUTH_GUARD', 'web'),
        'table' => env('SECURITY_USERS_TABLE', 'users'),
    ],

    /*
    |--------------------------------------------------------------------------
    | Administration Dashboard & Routing
    |--------------------------------------------------------------------------
    |
    | Settings governing the web dashboard, route prefixes, and access gates.
    |
    */
    'admin' => [
        'enabled' => env('SECURITY_ADMIN_ENABLED', true),
        'prefix' => env('SECURITY_ADMIN_PREFIX', 'admin'),
        'route_name_prefix' => env('SECURITY_ROUTE_NAME_PREFIX', 'admin.'),
        'middleware' => ['web', 'auth'],
        'permissions_enabled' => env('SECURITY_PERMISSIONS_ENABLED', true),
        'superadmin_bypass' => env('SECURITY_SUPERADMIN_BYPASS', true),
    ],

    /*
    |--------------------------------------------------------------------------
    | Content Security Policy (CSP) Directives
    |--------------------------------------------------------------------------
    |
    | Enforced by SecureHeadersMiddleware on every response unless overridden.
    |
    */
    'csp' => [
        'default-src' => ["'self'"],
        'base-uri' => ["'self'"],
        'object-src' => ["'none'"],
        'frame-ancestors' => ["'self'"],
        'img-src' => [
            "'self'",
            'data:',
            'https:',
            'blob:',
        ],
        'script-src' => [
            "'self'",
            "'unsafe-inline'",
            "'unsafe-eval'",
            'https://www.googletagmanager.com',
            'https://www.google-analytics.com',
            'https://googleads.g.doubleclick.net',
            'https://cdn.jsdelivr.net',
            'https://cdnjs.cloudflare.com',
            'https://challenges.cloudflare.com',
        ],
        'style-src' => [
            "'self'",
            "'unsafe-inline'",
            'https://fonts.googleapis.com',
            'https://cdn.jsdelivr.net',
            'https://cdnjs.cloudflare.com',
        ],
        'font-src' => [
            "'self'",
            'https://fonts.gstatic.com',
            'data:',
        ],
        'connect-src' => [
            "'self'",
            'https://www.google-analytics.com',
            'https://analytics.google.com',
            'https://www.googleadservices.com',
            'https://googleads.g.doubleclick.net',
            'https://ad.doubleclick.net',
            'https://www.google.com',
            'https://api.ipify.org/',
            'https://cdn.jsdelivr.net',
            'https://cdnjs.cloudflare.com',
            'https://challenges.cloudflare.com',
            'blob:',
        ],
        'frame-src' => [
            "'self'",
            'https://www.youtube.com',
            'https://www.youtube-nocookie.com',
            'https://www.facebook.com',
            'https://challenges.cloudflare.com',
        ],
        'media-src' => ["'self'"],
        'form-action' => ["'self'"],
    ],

    /*
    |--------------------------------------------------------------------------
    | Bot / Automation Detection
    |--------------------------------------------------------------------------
    |
    | Matched case-insensitively against the request User-Agent.
    | Allowed crawlers bypass blocking to safeguard SEO rankings.
    |
    */
    'bots' => [
        'block_empty_user_agent' => true,
        'blocked_patterns' => [
            'curl/',
            'wget/',
            'python-requests',
            'python-urllib',
            'aiohttp',
            'scrapy',
            'httpclient',
            'go-http-client',
            'java/',
            'okhttp',
            'postmanruntime',
            'insomnia',
            'headlesschrome',
            'phantomjs',
            'sqlmap',
            'nikto',
            'nmap',
            'masscan',
            'zgrab',
            'libwww-perl',
        ],
        'allowed_crawlers' => [
            'googlebot',
            'bingbot',
            'slurp',
            'duckduckbot',
            'baiduspider',
            'yandexbot',
            'sogou',
            'exabot',
            'facebookexternalhit',
            'facebot',
            'twitterbot',
            'linkedinbot',
            'whatsapp',
            'applebot',
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | IP Geolocation
    |--------------------------------------------------------------------------
    */
    'geo' => [
        'enabled' => env('GEO_IP_ENABLED', true),
        'endpoint' => 'http://ip-api.com/json',
        'cache_hours' => 24,
        'timeout' => 3,
    ],

    /*
    |--------------------------------------------------------------------------
    | HTTP Security Headers
    |--------------------------------------------------------------------------
    */
    'headers' => [
        'X-Frame-Options' => 'DENY',
        'X-Content-Type-Options' => 'nosniff',
        'X-XSS-Protection' => '0',
        'Referrer-Policy' => 'strict-origin-when-cross-origin',
        'Permissions-Policy' => 'geolocation=(self), microphone=(), camera=(), payment=(), usb=()',
        'Cross-Origin-Opener-Policy' => 'same-origin',
        'X-Permitted-Cross-Domain-Policies' => 'none',
    ],

    'hsts' => env('SECURITY_HSTS', 'max-age=31536000; includeSubDomains'),

    /*
    |--------------------------------------------------------------------------
    | Security Events, Incidents & Notifications
    |--------------------------------------------------------------------------
    */
    'events' => [
        'max_per_fingerprint_per_minute' => 20,
        'retention_days' => (int) env('SECURITY_EVENT_RETENTION_DAYS', 365),
        'dashboard_poll_seconds' => 15,
    ],

    'notifications' => [
        'mail_to' => env('SECURITY_ALERT_EMAILS', ''),
        'min_severity' => env('SECURITY_ALERT_MIN_SEVERITY', 'high'),
        'throttle_minutes' => 30,
    ],

    /*
    |--------------------------------------------------------------------------
    | Exploit Request Detection (WAF Layer)
    |--------------------------------------------------------------------------
    */
    'exploit_protection' => [
        'enabled' => env('SECURITY_EXPLOIT_PROTECTION', true),
        'mode_query' => env('SECURITY_EXPLOIT_MODE_QUERY', 'block'),
        'mode_body' => env('SECURITY_EXPLOIT_MODE_BODY', 'log'),
        'rich_fields' => ['content', 'description', 'answer', 'value', 'content_blocks', 'message', 'body', 'frontend_content'],
        'skip_fields' => ['password', 'password_confirmation', 'current_password', '_token', 'token', 'base64image'],
        'except' => [],
        'max_inspect_bytes' => 65536,
    ],

    /*
    |--------------------------------------------------------------------------
    | Periodic Security Monitoring
    |--------------------------------------------------------------------------
    */
    'monitoring' => [
        'failed_logins_per_ip' => 10,
        'distinct_accounts_per_ip' => 5,
        'window_minutes' => 15,
        'imunify' => [
            'enabled' => env('SECURITY_IMUNIFY_ENABLED', true),
            'binary' => env('SECURITY_IMUNIFY_BIN', 'imunify360-agent'),
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Database Content Review (php artisan security:scan-content)
    |--------------------------------------------------------------------------
    */
    'content_sources' => [
        ['table' => 'blogs', 'key' => 'id', 'field' => 'description', 'type' => 'html', 'profile' => 'rich'],
        ['table' => 'faqs', 'key' => 'id', 'field' => 'answer', 'type' => 'html', 'profile' => 'rich'],
        ['table' => 'pages', 'key' => 'id', 'field' => 'content_blocks', 'type' => 'blocks', 'profile' => 'rich'],
        ['table' => 'settings', 'key' => 'id', 'field' => 'value', 'type' => 'setting', 'profile' => 'rich'],
        ['table' => 'blogs', 'key' => 'id', 'field' => 'title', 'type' => 'text'],
        ['table' => 'blogs', 'key' => 'id', 'field' => 'meta_description', 'type' => 'text'],
        ['table' => 'pages', 'key' => 'id', 'field' => 'page_name', 'type' => 'text'],
        ['table' => 'faqs', 'key' => 'id', 'field' => 'question', 'type' => 'text'],
        ['table' => 'contacts', 'key' => 'id', 'field' => 'message', 'type' => 'text'],
        ['table' => 'users', 'key' => 'id', 'field' => 'name', 'type' => 'text'],
    ],

    /*
    |--------------------------------------------------------------------------
    | HTML Sanitizer (HTMLPurifier Profiles)
    |--------------------------------------------------------------------------
    */
    'html_sanitizer' => [
        'profiles' => [
            'rich' => [
                'allowed' => 'p[style|class],br,strong,b,em,i,u,s,strike,sub,sup,small,'
                    .'h1[style|class],h2[style|class],h3[style|class],h4[style|class],h5[style|class],h6[style|class],'
                    .'ul[style|class],ol[style|class|start],li[style|class],blockquote[style|class],pre[class],code[class],hr,'
                    .'a[href|title|target|rel|class],'
                    .'img[src|alt|title|width|height|style|class],figure[class|style],figcaption,'
                    .'table[style|class|border|cellpadding|cellspacing|width],thead,tbody,tfoot,caption,'
                    .'tr[style|class],th[style|class|colspan|rowspan|scope],td[style|class|colspan|rowspan],'
                    .'span[style|class],div[style|class],'
                    .'iframe[src|width|height|frameborder|allowfullscreen|title]',
                'css' => [
                    'text-align', 'color', 'background-color', 'font-weight', 'font-style', 'text-decoration',
                    'font-size', 'width', 'height', 'max-width', 'margin', 'margin-left', 'margin-right',
                    'margin-top', 'margin-bottom', 'padding', 'padding-left', 'padding-right', 'padding-top',
                    'padding-bottom', 'border', 'border-collapse', 'float', 'list-style-type', 'vertical-align',
                ],
                'iframe_hosts' => ['www.youtube.com/embed', 'www.youtube-nocookie.com/embed', 'player.vimeo.com/video'],
            ],
            'basic' => [
                'allowed' => 'p,br,strong,b,em,i,u,ul,ol,li,a[href|title],code,blockquote',
                'css' => [],
            ],
            'plain' => [
                'allowed' => '',
                'css' => [],
            ],
        ],
    ],

    /*
    |--------------------------------------------------------------------------
    | Upload Safety Policy
    |--------------------------------------------------------------------------
    */
    'uploads' => [
        'clamav_required' => env('SECURITY_UPLOAD_CLAMAV_REQUIRED', false),
        'max_archive_entries' => 1000,
        'max_archive_uncompressed_bytes' => 200 * 1024 * 1024,
    ],

    /*
    |--------------------------------------------------------------------------
    | File Scanner & Antivirus (php artisan security:scan)
    |--------------------------------------------------------------------------
    */
    'scanner' => [
        'roots' => [
            'app', 'bootstrap', 'config', 'database', 'routes', 'resources', 'public', 'storage/app',
        ],
        'exclude' => [
            'bootstrap/cache', 'storage/framework', 'storage/logs', 'storage/quarantine',
            'storage/app/quarantine', 'node_modules', 'vendor', '.git', 'public/vendor',
        ],
        'upload_roots' => ['storage/app/public', 'storage/app/private', 'storage/app/uploads'],
        'allowed_public_php' => ['public/index.php', 'public/admin/ckeditor/plugins/imgbrowse/imgbrowse.php'],
        'critical_files' => [
            'public/index.php', 'public/.htaccess', 'artisan', 'bootstrap/app.php', 'bootstrap/providers.php',
            'composer.json', 'composer.lock', 'storage/app/public/.htaccess',
        ],
        'critical_dirs' => ['config', 'routes', 'app/Http/Middleware', 'app/Providers'],
        'max_file_bytes' => (int) env('SECURITY_SCAN_MAX_FILE_BYTES', 8 * 1024 * 1024),
        'max_runtime_seconds' => (int) env('SECURITY_SCAN_MAX_RUNTIME', 1800),
        'checkpoint_every' => 200,
        'throttle_every' => 500,
        'throttle_microseconds' => 20000,
        'lock_seconds' => 3600,
        'watch_poll_seconds' => (int) env('SECURITY_WATCH_POLL_SECONDS', 15),
        'watch_debounce_seconds' => 2,
        'stale_run_minutes' => 120,
        'full_scan_max_age_hours' => 30,
        'quarantine_path' => env('SECURITY_QUARANTINE_PATH', storage_path('quarantine')),
        'auto_quarantine' => [
            'enabled' => env('SECURITY_AUTO_QUARANTINE', true),
            'min_confidence' => 90,
        ],
        'clamav' => [
            'enabled' => env('SECURITY_CLAMAV_ENABLED', true),
            'clamdscan' => env('SECURITY_CLAMDSCAN_BIN', 'clamdscan'),
            'clamscan' => env('SECURITY_CLAMSCAN_BIN', 'clamscan'),
            'timeout' => 120,
        ],
        'inotifywait' => env('SECURITY_INOTIFYWAIT_BIN', 'inotifywait'),
        'alert_poll_seconds' => 60,
    ],

];