<?php

namespace ThePrimeStudio\LaravelSentinel\Services;

use ThePrimeStudio\LaravelSentinel\Contracts\SanitizerInterface;

/**
 * Static content analysis for web shells, obfuscation and disguised executables.
 *
 * Pure function of (path, content, context): never includes, evaluates or executes
 * the analysed content. Each rule contributes a weighted signal; the file's confidence
 * is the strongest signal plus a damped share of the others. Signals that only prove a
 * dangerous function *name* exists are "weak" and can never push a file over the
 * reporting threshold on their own.
 */
class HeuristicAnalyzer
{
    /** Minimum confidence for a file to be reported as a finding. */
    public const REPORT_THRESHOLD = 40;

    /** Upper bound for confidence derived only from weak signals. */
    public const WEAK_ONLY_CAP = 25;

    /** Extensions a typical PHP/Apache/nginx stack may execute or interpret server-side. */
    public const SERVER_EXECUTABLE_EXTENSIONS = [
        'php', 'php3', 'php4', 'php5', 'php56', 'php7', 'php71', 'php8', 'phtml', 'pht', 'phps', 'phar',
        'shtml', 'shtm', 'stm', 'cgi', 'pl', 'py', 'sh', 'jsp', 'asp', 'aspx',
    ];

    /** Extensions that should only ever contain inert media/document bytes. */
    public const MEDIA_EXTENSIONS = [
        'jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'ico', 'heic', 'heif', 'svg', 'pdf', 'txt', 'csv',
        'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'mp4', 'mp3', 'webm', 'zip',
    ];

    /**
     * @param  array{in_upload_root?: bool, is_config_file?: bool}  $context
     * @return array{confidence: int, severity: ?string, category: ?string, rule: ?string, signals: list<array{rule: string, category: string, weight: int, weak: bool, reason: string, evidence: ?string}>}
     */
    public function analyze(string $path, string $content, array $context = []): array
    {
        $signals = [];
        $basename = strtolower(basename($path));
        $ext = strtolower(pathinfo($basename, PATHINFO_EXTENSION));
        $inUpload = (bool) ($context['in_upload_root'] ?? false);
        $isPhpFile = in_array($ext, ['php', 'php3', 'php4', 'php5', 'php56', 'php7', 'php71', 'php8', 'phtml', 'pht', 'phps', 'phar', 'inc'], true);
        $hasPhpTag = $this->containsPhpOpenTag($content);

        $add = function (string $rule, string $category, int $weight, string $reason, ?string $evidence = null, bool $weak = false) use (&$signals) {
            $signals[] = compact('rule', 'category', 'weight', 'weak', 'reason', 'evidence');
        };

        // ── Placement rules ────────────────────────────────────────────────
        if ($inUpload && in_array($ext, self::SERVER_EXECUTABLE_EXTENSIONS, true)) {
            $add('upload.executable_extension', 'executable_upload', 75,
                "Server-executable extension .{$ext} inside an upload directory.");
        }

        if ($hasPhpTag && in_array($ext, self::MEDIA_EXTENSIONS, true)) {
            $add('disguised.php_in_media', 'disguised_media', 95,
                "PHP code inside a file with media/document extension .{$ext} (polyglot or disguised payload).",
                $this->snippetAround($content, '<?'));
        } elseif ($hasPhpTag && $inUpload) {
            $add('upload.php_code', 'webshell', 85,
                'PHP code found inside an upload directory.', $this->snippetAround($content, '<?'));
        }

        if (preg_match('/<!--\s*#\s*(exec|include|config|echo)\b/i', $content, $m)) {
            $add('ssi.directive', 'webshell', $inUpload ? 85 : 55,
                'Server-Side Include directive (can execute commands under mod_include).', $this->snippetAround($content, $m[0]));
        }

        // ── Server config persistence (.htaccess / .user.ini) ──────────────
        if (in_array($basename, ['.htaccess', '.user.ini', 'php.ini'], true) && empty($context['is_config_file'])) {
            if (preg_match('/^\s*(AddHandler|SetHandler|AddType)\b[^\n]*(php|x-httpd|phtml|cgi-script)/im', $content, $m)
                || preg_match('/^\s*(php_value\s+)?(auto_prepend_file|auto_append_file)\b/im', $content, $m)) {
                $add('config.handler_override', 'persistence', 90,
                    "{$basename} maps files to an executable handler or auto-prepends code.", trim($m[0]));
            } elseif ($inUpload) {
                $add('upload.server_config', 'persistence', 60,
                    "{$basename} placed inside an upload directory.");
            }
        }

        // PHP-specific rules only apply where PHP code is actually present.
        if ($isPhpFile || $hasPhpTag) {
            $this->analyzePhp($content, $add);
        }

        return $this->score($signals);
    }

    /**
     * @param  callable(string, string, int, string, ?string=, bool=): void  $add
     */
    protected function analyzePhp(string $content, callable $add): void
    {
        $input = '\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER\s*\[\s*[\'"]HTTP_)';
        $decoder = '(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|hex2bin|convert_uudecode|strrev)';

        if (preg_match('/\b(?:eval|assert|create_function)\s*\(\s*(?:@\s*)?(?:'.$input.'|'.$decoder.'\s*\()/i', $content, $m)) {
            $add('php.eval_dynamic', 'webshell', 92,
                'eval/assert executes request input or decoded data.', $this->snippetAround($content, $m[0]));
        }

        if (preg_match('/\b(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(\s*(?:@\s*)?[^;]{0,60}?'.$input.'/i', $content, $m)) {
            $add('php.command_from_input', 'webshell', 92,
                'OS command executed with request input.', $this->snippetAround($content, $m[0]));
        }

        if (preg_match('/`[^`\n]{0,80}'.$input.'/i', $content, $m)) {
            $add('php.backtick_input', 'webshell', 88,
                'Backtick shell execution with request input.', $this->snippetAround($content, $m[0]));
        }

        if (preg_match('/'.$input.'\s*\[[^\]]{1,40}\]\s*\(/i', $content, $m)) {
            $add('php.callable_from_input', 'webshell', 88,
                'Function name taken from request input and called.', $this->snippetAround($content, $m[0]));
        }

        if (preg_match('/\b(?:include|include_once|require|require_once)\s*\(?\s*'.$input.'/i', $content, $m)) {
            $add('php.include_input', 'webshell', 80,
                'File include path taken from request input.', $this->snippetAround($content, $m[0]));
        }

        if (preg_match('/\bpreg_replace\s*\(\s*([\'"])(.).*?\2[a-z]*e[a-z]*\1/is', $content, $m)) {
            $add('php.preg_e', 'webshell', 70,
                'preg_replace with /e modifier (code execution).', $this->snippetAround($content, $m[0]));
        }

        if (preg_match('/'.$decoder.'\s*\(\s*'.$decoder.'\s*\(/i', $content, $m)) {
            $add('obf.decoder_chain', 'obfuscation', 55,
                'Nested decoding functions (typical payload unpacking).', $this->snippetAround($content, $m[0]));
        }

        if (preg_match('/[\'"][A-Za-z0-9+\/=]{2000,}[\'"]/', $content)) {
            $add('obf.long_base64', 'obfuscation', 35, 'Very long base64-like string literal (embedded payload).');
        }

        if (preg_match_all('/\\\\x[0-9a-f]{2}/i', $content) >= 60) {
            $add('obf.hex_escapes', 'obfuscation', 35, 'Dense hex-escaped string content.');
        }

        if (preg_match_all('/\bchr\s*\(\s*\d+\s*\)\s*\./i', $content) >= 20) {
            $add('obf.chr_chain', 'obfuscation', 35, 'Long chr() concatenation chain (string hiding).');
        }

        if (preg_match_all('/\bgoto\s+\w+\s*;/i', $content) >= 20) {
            $add('obf.goto_flow', 'obfuscation', 30, 'Heavy goto-based control flow (obfuscator output).');
        }

        foreach (preg_split('/\R/', $content) as $line) {
            if (strlen($line) > 5000) {
                $add('obf.long_line', 'obfuscation', 20, 'Single source line longer than 5000 characters.');
                break;
            }
        }

        // Known web-shell family markers. Built by concatenation so this file does not match itself.
        $markers = [
            'Files'.'Man', 'c99'.'shell', 'r57'.'shell', 'b374'.'k', 'Indo'.'Xploit', 'Alfa'.'Shell',
            'WSO '.'shell', 'P.A.'.'S. v', 'weev'.'ely', 'china'.'chopper', 'Mini '.'Shell',
        ];
        foreach ($markers as $marker) {
            if (stripos($content, $marker) !== false) {
                $add('marker.known_webshell', 'webshell', 85, "Known web-shell family marker: {$marker}.",
                    $this->snippetAround($content, $marker));
                break;
            }
        }

        // Weak: function names only. Common in legitimate code (Laravel, Symfony, Composer).
        if (preg_match_all('/\b(eval|assert|system|shell_exec|passthru|proc_open|popen|base64_decode)\s*\(/i', $content, $mm)) {
            $names = array_values(array_unique(array_map('strtolower', $mm[1])));
            $add('func.dangerous_name', 'informational', min(5 * count($names), 15),
                'Uses sensitive functions: '.implode(', ', $names).' (not malicious by itself).', null, true);
        }
    }

    /**
     * @param  list<array{rule: string, category: string, weight: int, weak: bool, reason: string, evidence: ?string}>  $signals
     */
    protected function score(array $signals): array
    {
        if ($signals === []) {
            return ['confidence' => 0, 'severity' => null, 'category' => null, 'rule' => null, 'signals' => []];
        }

        usort($signals, fn ($a, $b) => $b['weight'] <=> $a['weight']);
        $top = $signals[0];
        $rest = array_sum(array_column(array_slice($signals, 1), 'weight'));
        $confidence = (int) min(100, $top['weight'] + round($rest * 0.25));

        $strong = array_filter($signals, fn ($s) => ! $s['weak']);
        if ($strong === []) {
            $confidence = min($confidence, self::WEAK_ONLY_CAP);
        }

        return [
            'confidence' => $confidence,
            'severity' => self::severityFor($confidence),
            'category' => $top['category'],
            'rule' => $top['rule'],
            'signals' => $signals,
        ];
    }

    public static function severityFor(int $confidence): ?string
    {
        return match (true) {
            $confidence >= 85 => 'critical',
            $confidence >= 65 => 'high',
            $confidence >= self::REPORT_THRESHOLD => 'medium',
            $confidence >= 20 => 'low',
            default => null,
        };
    }

    public function containsPhpOpenTag(string $content): bool
    {
        // <?php, <?= and short "<? " tags followed by code-like content. Compressed media can contain
        // "<?=" by chance, so the bytes after the tag must be mostly printable ASCII to count.
        if (! preg_match_all('/<\?(?:php\b|=|\s+[\$a-z_])/i', $content, $matches, PREG_OFFSET_CAPTURE)) {
            return false;
        }

        foreach ($matches[0] as [$tag, $offset]) {
            $tail = substr($content, $offset + strlen($tag), 48);
            if ($tail === '') {
                continue;
            }
            $printable = preg_match_all('/[\x20-\x7E\t\r\n]/', $tail);
            if ($printable / strlen($tail) >= 0.85) {
                return true;
            }
        }

        return false;
    }

    /** A short, printable excerpt for evidence. Never executed; escaped on display. */
    protected function snippetAround(string $content, string $needle, int $radius = 120): string
    {
        $pos = stripos($content, $needle);
        $pos = $pos === false ? 0 : $pos;
        $start = max(0, $pos - $radius);
        $snippet = substr($content, $start, strlen($needle) + $radius * 2);
        $snippet = preg_replace('/[^\P{C}\n\t]/u', '.', mb_convert_encoding($snippet, 'UTF-8', 'UTF-8')) ?? '';

        return mb_substr($snippet, 0, 400);
    }
}
