<?php

namespace ThePrimeStudio\LaravelSentinel\Tests\Unit;

use ThePrimeStudio\LaravelSentinel\Services\HtmlSanitizer;
use PHPUnit\Framework\TestCase;

class HtmlSanitizerTest extends TestCase
{
    protected HtmlSanitizer $sanitizer;

    protected function setUp(): void
    {
        parent::setUp();
        $this->sanitizer = new HtmlSanitizer();
    }

    public function test_removes_script_tags(): void
    {
        $html = '<p>Normal text <script>alert(1)</script></p>';
        $clean = $this->sanitizer->sanitize($html, 'rich');

        $this->assertStringNotContainsString('<script>', $clean);
        $this->assertStringContainsString('Normal text', $clean);
    }

    public function test_removes_inline_event_handlers(): void
    {
        $html = '<a href="https://example.com" onclick="alert(1)">Link</a>';
        $clean = $this->sanitizer->sanitize($html, 'rich');

        $this->assertStringNotContainsString('onclick', $clean);
        $this->assertStringContainsString('href="https://example.com"', $clean);
    }

    public function test_detects_dangerous_javascript_payload(): void
    {
        $payload = '<img src="x" onerror="alert(1)">';
        $this->assertTrue($this->sanitizer->isDangerous($payload));

        $reasons = $this->sanitizer->detect($payload);
        $this->assertNotEmpty($reasons);
    }
}