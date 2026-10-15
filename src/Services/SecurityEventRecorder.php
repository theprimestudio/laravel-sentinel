<?php

namespace ThePrimeStudio\LaravelSentinel\Services;

use ThePrimeStudio\LaravelSentinel\Models\Incident;
use ThePrimeStudio\LaravelSentinel\Models\IncidentNote;
use ThePrimeStudio\LaravelSentinel\Models\SecurityEvent;
use ThePrimeStudio\LaravelSentinel\Notifications\SecurityIncidentNotification;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Notification;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\Str;

/**
 * Single entry point for security telemetry.
 *
 *  - Redacts secrets (passwords, tokens, cookies, session ids) and truncates payloads.
 *  - Groups repeats into incidents by fingerprint; flood control stores at most N events per
 *    fingerprint per minute and counts the rest on the incident (suppressed_count).
 *  - Appends to a SHA-256 hash chain so edits/deletions of stored events are detectable.
 *  - Notifies (queued mail) on new/escalated incidents at or above the configured severity,
 *    throttled per incident.
 *  - Never throws into the caller: telemetry failure must not break the user's request.
 */
use ThePrimeStudio\LaravelSentinel\Contracts\EventRecorderInterface;

class SecurityEventRecorder implements EventRecorderInterface
{
    public const SENSITIVE_KEYS = '/(pass(word)?|pwd|token|secret|session|cookie|authorization|api[-_]?key|otp|code|_token|credit|card|cvv)/i';

    /** Recursion guard (e.g. a write inside notification sending). */
    protected bool $recording = false;

    public function record(string $type, string $severity, string $reason, array $context = [], string $action = 'logged', ?string $sourceIp = null): ?SecurityEvent
    {
        if ($this->recording || ! $this->tablesReady()) {
            return null;
        }
        $this->recording = true;

        try {
            $request = app()->runningInConsole() && ! app()->runningUnitTests() ? null : request();
            $ip = $sourceIp ?? $request?->ip();
            $route = $request?->route()?->getName() ?? ($request ? '/'.ltrim($request->path(), '/') : null);
            $severity = in_array($severity, ['critical', 'high', 'medium', 'low'], true) ? $severity : 'low';

            $fingerprint = hash('sha256', implode('|', [$type, $ip, Str::limit(preg_replace('/\d+/', '#', $reason) ?? $reason, 200, ''), $route]));
            $incident = $this->incidentFor($fingerprint, $type, $severity, $reason, $ip);

            // Flood control: beyond the per-minute budget only the incident counter moves.
            $limitKey = 'security-event:'.$fingerprint;
            if (RateLimiter::tooManyAttempts($limitKey, (int) config('security.events.max_per_fingerprint_per_minute', 20))) {
                $incident->increment('suppressed_count');

                return null;
            }
            RateLimiter::hit($limitKey, 60);

            $attributes = [
                'occurred_at' => now(),
                'type' => $type,
                'severity' => $severity,
                'source_ip' => $ip,
                'user_id' => $request?->user()?->getAuthIdentifier() ?? auth()->id(),
                'method' => $request?->method(),
                'route' => $route ? Str::limit($route, 190, '') : null,
                'path' => $request ? Str::limit('/'.ltrim($request->path(), '/'), 490, '') : null,
                'reason' => Str::limit($reason, 2000),
                'action' => $action,
                'context' => self::redact($context),
                'fingerprint' => $fingerprint,
                'incident_id' => $incident->id,
            ];

            return Cache::lock('security-events-chain', 10)->block(5, function () use ($attributes) {
                $prev = SecurityEvent::query()->latest('id')->value('hash');
                $attributes['prev_hash'] = $prev;
                $attributes['hash'] = hash('sha256', ($prev ?? '').SecurityEvent::canonical($attributes));

                return SecurityEvent::create($attributes);
            });
        } catch (\Throwable $e) {
            Log::error('[security] failed to record security event', ['type' => $type, 'error' => $e->getMessage()]);

            return null;
        } finally {
            $this->recording = false;
        }
    }

    protected function incidentFor(string $fingerprint, string $type, string $severity, string $reason, ?string $ip): Incident
    {
        return DB::transaction(function () use ($fingerprint, $type, $severity, $reason, $ip) {
            $incident = Incident::where('fingerprint', $fingerprint)->unresolved()->lockForUpdate()->first();
            $now = now();

            if (! $incident) {
                $incident = Incident::create([
                    'fingerprint' => $fingerprint, 'type' => $type, 'severity' => $severity,
                    'title' => Str::limit(Str::headline($type).': '.$reason, 250),
                    'status' => 'open', 'source_ip' => $ip, 'event_count' => 1,
                    'first_seen_at' => $now, 'last_seen_at' => $now,
                ]);
                IncidentNote::create(['incident_id' => $incident->id, 'action' => 'created', 'created_at' => $now]);
                $this->notify($incident, true);

                return $incident;
            }

            $escalated = Incident::SEVERITY_RANK[$severity] > (Incident::SEVERITY_RANK[$incident->severity] ?? 0);
            $incident->forceFill([
                'event_count' => $incident->event_count + 1,
                'last_seen_at' => $now,
                'severity' => $escalated ? $severity : $incident->severity,
            ])->save();

            if ($escalated) {
                IncidentNote::create(['incident_id' => $incident->id, 'action' => 'escalated', 'meta' => ['severity' => $severity], 'created_at' => $now]);
                $this->notify($incident, true);
            }

            return $incident;
        });
    }

    protected function notify(Incident $incident, bool $isNewOrEscalated): void
    {
        $recipients = array_filter(array_map('trim', explode(',', (string) config('security.notifications.mail_to', ''))));
        $min = Incident::SEVERITY_RANK[config('security.notifications.min_severity', 'high')] ?? 3;
        $throttle = (int) config('security.notifications.throttle_minutes', 30);

        if (! $isNewOrEscalated || $recipients === [] || (Incident::SEVERITY_RANK[$incident->severity] ?? 0) < $min) {
            return;
        }
        if ($incident->notified_at && $incident->notified_at->gt(now()->subMinutes($throttle))) {
            return;
        }

        try {
            Notification::route('mail', $recipients)->notify(new SecurityIncidentNotification($incident));
            $incident->forceFill(['notified_at' => now()])->save();
            IncidentNote::create(['incident_id' => $incident->id, 'action' => 'notified', 'meta' => ['channels' => ['mail'], 'recipients' => count($recipients)], 'created_at' => now()]);
        } catch (\Throwable $e) {
            // Queue/mail failure must not lose the event; it is visible in the dashboard health.
            Log::error('[security] incident notification failed', ['incident' => $incident->id, 'error' => $e->getMessage()]);
            Cache::put('security:notifications:last_failure', ['at' => now()->timestamp, 'error' => Str::limit($e->getMessage(), 300)], 86400);
        }
    }

    /** Recursively redact sensitive keys and bound sizes. */
    public static function redact(array $data, int $depth = 0): array
    {
        $out = [];
        foreach (array_slice($data, 0, 50, true) as $key => $value) {
            if (is_string($key) && preg_match(self::SENSITIVE_KEYS, $key)) {
                $out[$key] = '[REDACTED]';
            } elseif (is_array($value)) {
                $out[$key] = $depth < 3 ? self::redact($value, $depth + 1) : '[…]';
            } elseif (is_string($value)) {
                $out[$key] = Str::limit($value, 500);
            } elseif (is_scalar($value) || $value === null) {
                $out[$key] = $value;
            } else {
                $out[$key] = '['.get_debug_type($value).']';
            }
        }

        return $out;
    }

    /**
     * Verify the hash chain over the most recent $limit events.
     *
     * @return array{ok: bool, checked: int, broken_at: ?int}
     */
    public function verifyChain(int $limit = 5000): array
    {
        $events = SecurityEvent::query()->latest('id')->limit($limit)->get()->reverse()->values();
        $checked = 0;
        foreach ($events as $i => $event) {
            $attributes = $event->getAttributes();
            $attributes['context'] = $event->context;
            $attributes['occurred_at'] = $event->occurred_at;
            $expected = hash('sha256', ($event->prev_hash ?? '').SecurityEvent::canonical($attributes));
            $linkOk = $i === 0 || $event->prev_hash === $events[$i - 1]->hash;
            if ($expected !== $event->hash || ! $linkOk) {
                return ['ok' => false, 'checked' => $checked, 'broken_at' => $event->id];
            }
            $checked++;
        }

        return ['ok' => true, 'checked' => $checked, 'broken_at' => null];
    }

    protected function tablesReady(): bool
    {
        static $ready = null;

        return $ready ??= \Illuminate\Support\Facades\Schema::hasTable('security_events');
    }
}
