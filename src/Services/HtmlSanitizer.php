<?php

namespace ThePrimeStudio\LaravelSentinel\Services;

use HTMLPurifier;
use HTMLPurifier_Config;

/**
 * Allowlist HTML sanitiser (HTMLPurifier) with field-specific profiles.
 *
 * Sanitisation is the control: anything not explicitly allowed (tags, attributes, CSS
 * properties, URL schemes) is removed, after HTMLPurifier normalises encodings and
 * malformed markup. detect() is a separate, best-effort reporter used for logging and
 * database review; it never decides what is safe.
 *
 * Profiles:
 *  - rich:  CKEditor article/page content (formatting, links, images, tables, YouTube embeds)
 *  - basic: short formatted text (comments, answers): no images, tables or embeds
 *  - plain: no HTML at all (text is kept, tags removed)
 */
use ThePrimeStudio\LaravelSentinel\Contracts\SanitizerInterface;

class HtmlSanitizer implements SanitizerInterface
{
    /** @var array<string, HTMLPurifier> */
    protected array $purifiers = [];

    public function sanitize(?string $html, string $profile = 'rich'): ?string
    {
        if ($html === null || $html === '') {
            return $html;
        }

        // Strip NUL and other C0 controls (except tab/newline) that browsers ignore but filters may not.
        $html = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F]/', '', $html) ?? '';

        $clean = $this->purifier($profile)->purify($html);

        // HTMLPurifier drops a non-allowlisted iframe src but keeps the element; remove the empty frame.
        $clean = preg_replace('#<iframe\b(?![^>]*\ssrc=)[^>]*>.*?</iframe>#is', '', $clean) ?? $clean;

        return trim($clean);
    }

    /**
     * Report dangerous constructs in raw input, including entity/percent-encoded variants.
     *
     * @return list<string> human-readable reasons (empty when nothing suspicious)
     */
    public function detect(?string $html): array
    {
        if ($html === null || $html === '') {
            return [];
        }

        $variants = [$html];
        $decoded = $html;
        for ($i = 0; $i < 3; $i++) {
            $next = html_entity_decode(rawurldecode($decoded), ENT_QUOTES | ENT_HTML5, 'UTF-8');
            if ($next === $decoded) {
                break;
            }
            $variants[] = $decoded = $next;
        }
        $haystack = strtolower(preg_replace('/[\x00-\x20]+/', ' ', implode("\n", $variants)) ?? '');
        $compact = preg_replace('/\s+/', '', $haystack) ?? '';

        $rules = [
            'script element' => '/<\s*script\b/',
            'inline event handler (on*=)' => '/<[^>]+[\s\/"\']on[a-z]+\s*=/',
            'javascript:/vbscript: URL' => '/(javascript|vbscript|livescript)\s*:/',
            'data:text/html or data:*script URL' => '/data\s*:\s*(text\/html|[a-z]+\/[a-z+\-]*script|image\/svg\+xml)/',
            'embedded object/applet/embed' => '/<\s*(object|embed|applet)\b/',
            'base/meta/link tag' => '/<\s*(base|meta|link)\b/',
            'form element' => '/<\s*(form|input|button|textarea|select)\b/',
            'SVG/MathML markup' => '/<\s*(svg|math)\b/',
            'iframe/frame element' => '/<\s*(i?frame|frameset)\b/',
            'srcdoc attribute' => '/\ssrcdoc\s*=/',
            'CSS expression/behavior/import' => '/(expression\s*\(|behavior\s*:|-moz-binding|@import)/',
            'PHP code tag' => '/<\?(php|=)/',
            'template/server-side include' => '/(<!--\s*#\s*(exec|include)|\{\{.*constructor|<%)/',
        ];

        $reasons = [];
        foreach ($rules as $reason => $pattern) {
            if (preg_match($pattern, $haystack)) {
                $reasons[] = $reason;
            }
        }
        // Obfuscated scheme split by whitespace/controls, e.g. "java\tscript:".
        if (! in_array('javascript:/vbscript: URL', $reasons, true) && str_contains($compact, 'javascript:')) {
            $reasons[] = 'obfuscated javascript: URL';
        }

        return $reasons;
    }

    /** Whether sanitising would change the stored value in a security-relevant way. */
    public function isDangerous(?string $html): bool
    {
        return $this->detect($html) !== [];
    }

    protected function purifier(string $profile): HTMLPurifier
    {
        if (isset($this->purifiers[$profile])) {
            return $this->purifiers[$profile];
        }

        $config = HTMLPurifier_Config::createDefault();
        $cacheDir = storage_path('framework/cache/htmlpurifier');
        if (! is_dir($cacheDir)) {
            @mkdir($cacheDir, 0755, true);
        }
        $config->set('Cache.SerializerPath', is_writable($cacheDir) ? $cacheDir : null);
        $config->set('Core.Encoding', 'UTF-8');
        $config->set('HTML.Doctype', 'HTML 4.01 Transitional');
        $config->set('URI.AllowedSchemes', ['http' => true, 'https' => true, 'mailto' => true, 'tel' => true]);
        $config->set('URI.DisableExternalResources', false);
        $config->set('Attr.AllowedFrameTargets', ['_blank']);
        $config->set('HTML.TargetNoopener', true);
        $config->set('HTML.TargetNoreferrer', true);
        $config->set('Attr.EnableID', false);           // no id clobbering
        $config->set('AutoFormat.RemoveEmpty', false);

        $profiles = config('security.html_sanitizer.profiles', []);
        $definition = $profiles[$profile] ?? null;
        if ($definition === null) {
            throw new \InvalidArgumentException("Unknown HTML sanitizer profile [{$profile}]");
        }

        $config->set('HTML.Allowed', $definition['allowed']);
        if (! empty($definition['css'])) {
            $config->set('CSS.AllowedProperties', $definition['css']);
        }
        if (! empty($definition['iframe_hosts'])) {
            $hosts = implode('|', array_map(fn ($h) => preg_quote($h, '%'), $definition['iframe_hosts']));
            $config->set('HTML.SafeIframe', true);
            $config->set('URI.SafeIframeRegexp', '%^https://('.$hosts.')/%');
        }

        // Definition cache key must change whenever the profile changes.
        $config->set('HTML.DefinitionID', 'app-'.$profile);
        $config->set('HTML.DefinitionRev', crc32(serialize($definition)));
        if ($def = $config->maybeGetRawHTMLDefinition()) {
            $def->addElement('figure', 'Block', 'Flow', 'Common');
            $def->addElement('figcaption', 'Inline', 'Flow', 'Common');
            $def->addAttribute('iframe', 'allowfullscreen', 'Bool');
        }

        return $this->purifiers[$profile] = new HTMLPurifier($config);
    }
}
