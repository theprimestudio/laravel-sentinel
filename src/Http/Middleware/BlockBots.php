<?php

namespace ThePrimeStudio\LaravelSentinel\Http\Middleware;

use ThePrimeStudio\LaravelSentinel\Models\SecurityAlert;
use ThePrimeStudio\LaravelSentinel\Services\RequestContextService;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Facades\Schema;
use Symfony\Component\HttpFoundation\Response;

class BlockBots
{
    public function __construct(
        protected RequestContextService $context
    ) {}

    public function handle(Request $request, Closure $next): Response
    {
        $userAgent = trim((string) $request->userAgent());

        if ($this->context->isAllowedCrawler($userAgent)) {
            return $next($request);
        }

        $tool = $this->context->automationToolName($userAgent);

        if ($tool !== null) {
            $this->alert($request, $tool, $userAgent);

            return response()->json([
                'error' => 'Automated requests are not allowed.',
            ], 403);
        }

        return $next($request);
    }

    protected function alert(Request $request, string $tool, string $userAgent): void
    {
        if (! Schema::hasTable('security_alerts')) {
            return;
        }

        // Rate-limit alert creation to at most 1 per IP per minute to prevent DB flood DoS
        $rateLimitKey = 'bot_alert:' . ($request->ip() ?? 'unknown');

        if (RateLimiter::tooManyAttempts($rateLimitKey, maxAttempts: 1)) {
            return;
        }

        RateLimiter::hit($rateLimitKey, decaySeconds: 60);

        try {
            SecurityAlert::create([
                'severity'    => 'critical',
                'title'       => 'Blocked automated request',
                'description' => sprintf(
                    "Blocked automation tool [%s]\nIP: %s\nUser-Agent: %s\nURL: %s %s",
                    $tool,
                    $request->ip(),
                    $userAgent !== '' ? $userAgent : '(empty)',
                    $request->method(),
                    $request->fullUrl()
                ),
            ]);
        } catch (\Throwable $e) {
            // Never break the request cycle because alerting failed.
        }
    }
}
