<?php

namespace ThePrimeStudio\LaravelSentinel\Services;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class RequestContextService
{
    /**
     * Geolocate an IP address using ip-api.com (cached per IP).
     *
     * @return array{country: ?string, region: ?string, city: ?string, lat: ?float, lng: ?float, isp: ?string}|null
     */
    public function locationFromIp(?string $ip): ?array
    {
        if (! $ip || ! config('security.geo.enabled', true) || $this->isLocalIp($ip)) {
            return null;
        }

        return Cache::remember("geo_ip:{$ip}", now()->addHours((int) config('security.geo.cache_hours', 24)), function () use ($ip) {
            try {
                $response = Http::timeout((int) config('security.geo.timeout', 3))
                    ->get(config('security.geo.endpoint')."/{$ip}", [
                        'fields' => 'status,country,regionName,city,lat,lon,isp',
                    ]);

                if ($response->successful() && $response->json('status') === 'success') {
                    return [
                        'country' => $response->json('country'),
                        'region' => $response->json('regionName'),
                        'city' => $response->json('city'),
                        'lat' => $response->json('lat'),
                        'lng' => $response->json('lon'),
                        'isp' => $response->json('isp'),
                    ];
                }
            } catch (\Throwable $e) {
                Log::debug('IP geolocation lookup failed: '.$e->getMessage());
            }

            return null;
        });
    }

    /**
     * Location voluntarily shared by the user (browser geolocation, session).
     *
     * @return array{lat: float, lng: float}|null
     */
    public function locationFromUser(Request $request): ?array
    {
        if (! $request->hasSession()) {
            return null;
        }

        $lat = $request->session()->get('location_lat');
        $lng = $request->session()->get('location_lng');

        if ($lat === null || $lng === null) {
            return null;
        }

        return [
            'lat' => (float) $lat,
            'lng' => (float) $lng,
        ];
    }

    /**
     * Parse the User-Agent into device details.
     *
     * @return array{user_agent: ?string, browser: ?string, platform: ?string, device_type: string, is_mobile: bool, is_bot: bool, bot_name: ?string}
     */
    public function device(?string $userAgent): array
    {
        $ua = trim((string) $userAgent);

        $botName = $this->automationToolName($ua);
        $isCrawler = $this->isAllowedCrawler($ua);

        return [
            'user_agent' => $ua !== '' ? $ua : null,
            'browser' => $this->matchFirst($ua, [
                'Edg' => 'Edge',
                'OPR' => 'Opera',
                'Chrome' => 'Chrome',
                'Firefox' => 'Firefox',
                'Safari' => 'Safari',
                'MSIE' => 'IE',
                'Trident' => 'IE',
            ]),
            'platform' => $this->matchFirst($ua, [
                'Windows' => 'Windows',
                'Mac OS' => 'macOS',
                'Android' => 'Android',
                'iPhone' => 'iOS',
                'iPad' => 'iPadOS',
                'Linux' => 'Linux',
            ]),
            'device_type' => $this->deviceType($ua),
            'is_mobile' => (bool) preg_match('/Mobile|Android|iPhone|iPad/i', $ua),
            'is_bot' => $botName !== null || $isCrawler,
            'bot_name' => $botName ?? ($isCrawler ? 'crawler' : null),
        ];
    }

    /**
     * Name of the blocked automation tool matching the UA, if any.
     */
    public function automationToolName(string $ua): ?string
    {
        if ($ua === '') {
            return config('security.bots.block_empty_user_agent', true) ? 'empty-user-agent' : null;
        }

        foreach (config('security.bots.blocked_patterns', []) as $pattern) {
            if (stripos($ua, $pattern) !== false) {
                return $pattern;
            }
        }

        return null;
    }

    /**
     * Whether the UA belongs to a known good search/social crawler.
     */
    public function isAllowedCrawler(string $ua): bool
    {
        foreach (config('security.bots.allowed_crawlers', []) as $pattern) {
            if (stripos($ua, $pattern) !== false) {
                return true;
            }
        }

        return false;
    }

    /**
     * MailMessage lines describing where/why an OTP was requested.
     *
     * @return array<int, string>
     */
    public function securityNoticeLines(string $purpose): array
    {
        $request = request();
        $ip = $request?->ip();
        $device = $this->device($request?->userAgent());
        $ipLocation = $this->locationFromIp($ip);

        $site = setting('application-name') ?? config('app.name');
        $url = rtrim(setting('application-url') ?? config('app.url'), '/');

        $lines = [
            '**Purpose:** '.$purpose,
            '**Website:** ['.$site.']('.$url.')',
            '**IP Address:** '.($ip ?: 'Unknown'),
            '**Device:** '.($device['browser'] ?? 'Unknown').' on '.($device['platform'] ?? 'Unknown').' ('.$device['device_type'].')',
        ];

        if ($ipLocation) {
            $lines[] = '**Approx. Location (IP):** '.implode(', ', array_filter([
                $ipLocation['city'] ?? null,
                $ipLocation['region'] ?? null,
                $ipLocation['country'] ?? null,
            ]));
        }

        $userLocation = $request ? $this->locationFromUser($request) : null;

        if ($userLocation) {
            $lines[] = '**Location Shared By User:** '.$userLocation['lat'].', '.$userLocation['lng'];
        }

        return $lines;
    }

    protected function isLocalIp(string $ip): bool
    {
        return in_array($ip, ['127.0.0.1', '::1'], true)
            || filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false;
    }

    protected function matchFirst(string $ua, array $map): ?string
    {
        foreach ($map as $needle => $label) {
            if (stripos($ua, $needle) !== false) {
                return $label;
            }
        }

        return null;
    }

    protected function deviceType(string $ua): string
    {
        return match (true) {
            preg_match('/iPad|Tablet/i', $ua) === 1 => 'tablet',
            preg_match('/Mobile|Android|iPhone/i', $ua) === 1 => 'mobile',
            $ua === '' => 'unknown',
            default => 'desktop',
        };
    }
}
