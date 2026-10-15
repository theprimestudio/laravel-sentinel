<?php

namespace ThePrimeStudio\LaravelSentinel\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Registered as GLOBAL middleware so every response gets the headers: web, API, health
 * checks, file downloads, redirects, and error pages produced inside the pipeline.
 */
class SecureHeadersMiddleware
{
    /**
     * @param  Closure(Request): (Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $response = $next($request);

        foreach (config('security.headers', []) as $header => $value) {
            $response->headers->set($header, $value);
        }

        // Respect a stricter policy set by a specific response (e.g. sandboxed file serving).
        if (! $response->headers->has('Content-Security-Policy')) {
            $csp = collect(config('security.csp'))
                ->map(fn ($sources, $directive) => trim($directive.' '.implode(' ', (array) $sources)))
                ->implode('; ');
            $response->headers->set('Content-Security-Policy', $csp);
        }

        // HSTS must only be sent over HTTPS (RFC 6797 §7.2); isSecure() honours TrustProxies.
        if ($request->isSecure() && ($hsts = config('security.hsts'))) {
            $response->headers->set('Strict-Transport-Security', $hsts);
        } else {
            $response->headers->remove('Strict-Transport-Security');
        }

        $response->headers->remove('X-Powered-By');
        if (function_exists('header_remove') && ! headers_sent()) {
            header_remove('X-Powered-By');
        }

        return $response;
    }
}
