<?php

namespace ThePrimeStudio\LaravelSentinel\Tests\Feature;

use ThePrimeStudio\LaravelSentinel\Http\Middleware\BlockBots;
use ThePrimeStudio\LaravelSentinel\Http\Middleware\DetectExploitAttempts;
use ThePrimeStudio\LaravelSentinel\Http\Middleware\SecureHeadersMiddleware;
use ThePrimeStudio\LaravelSentinel\Tests\TestCase;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class WafMiddlewareTest extends TestCase
{
    public function test_secure_headers_are_added(): void
    {
        $middleware = app(SecureHeadersMiddleware::class);
        $request = Request::create('/test', 'GET');

        $response = $middleware->handle($request, function () {
            return new Response('ok');
        });

        $this->assertEquals('DENY', $response->headers->get('X-Frame-Options'));
        $this->assertEquals('nosniff', $response->headers->get('X-Content-Type-Options'));
        $this->assertNotEmpty($response->headers->get('Content-Security-Policy'));
    }

    public function test_exploit_detector_blocks_sql_injection_in_query(): void
    {
        $middleware = app(DetectExploitAttempts::class);
        $request = Request::create('/search?q=1 UNION SELECT null, username, password FROM users', 'GET');

        $response = $middleware->handle($request, function () {
            return new Response('passed');
        });

        $this->assertEquals(403, $response->getStatusCode());
    }

    public function test_bot_filter_blocks_sqlmap(): void
    {
        $middleware = app(BlockBots::class);
        $request = Request::create('/', 'GET');
        $request->headers->set('User-Agent', 'sqlmap/1.5#stable');

        $response = $middleware->handle($request, function () {
            return new Response('passed');
        });

        $this->assertEquals(403, $response->getStatusCode());
    }

    public function test_bot_filter_allows_googlebot(): void
    {
        $middleware = app(BlockBots::class);
        $request = Request::create('/', 'GET');
        $request->headers->set('User-Agent', 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)');

        $response = $middleware->handle($request, function () {
            return new Response('passed');
        });

        $this->assertEquals(200, $response->getStatusCode());
    }
}