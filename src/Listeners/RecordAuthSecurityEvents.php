<?php

namespace ThePrimeStudio\LaravelSentinel\Listeners;

use ThePrimeStudio\LaravelSentinel\Services\SecurityEventRecorder;
use Illuminate\Auth\Events\Failed;
use Illuminate\Auth\Events\Lockout;
use Illuminate\Auth\Events\PasswordReset;

/**
 * Feeds authentication activity into security events. Never records passwords; the
 * attempted identifier is masked so the dashboard does not become a credential list.
 */
class RecordAuthSecurityEvents
{
    public function __construct(protected SecurityEventRecorder $recorder) {}

    public function handleFailed(Failed $event): void
    {
        $this->recorder->record('failed_login', 'low', 'Failed login attempt', [
            'identifier' => self::mask((string) ($event->credentials['email'] ?? $event->credentials['username'] ?? '')),
            'known_account' => $event->user !== null,
            'target_user_id' => $event->user?->getAuthIdentifier(),
            'guard' => $event->guard,
        ], 'rejected');
    }

    public function handleLockout(Lockout $event): void
    {
        $this->recorder->record('lockout', 'medium', 'Login rate limit reached (lockout)', [
            'identifier' => self::mask((string) $event->request->input('email', '')),
        ], 'blocked');
    }

    public function handlePasswordReset(PasswordReset $event): void
    {
        $this->recorder->record('password_reset', 'low', 'Password was reset', [
            'target_user_id' => $event->user->getAuthIdentifier(),
        ]);
    }

    /** a***@ex***.com — enough to correlate, not enough to harvest. */
    public static function mask(string $identifier): string
    {
        if ($identifier === '') {
            return '';
        }
        [$local, $domain] = array_pad(explode('@', $identifier, 2), 2, '');
        $m = fn (string $s) => $s === '' ? '' : mb_substr($s, 0, 1).str_repeat('*', max(2, min(6, mb_strlen($s) - 1)));
        $tld = str_contains($domain, '.') ? substr($domain, strrpos($domain, '.')) : '';

        return $m($local).($domain !== '' ? '@'.$m(strstr($domain, '.', true) ?: $domain).$tld : '');
    }

    public function subscribe($events): array
    {
        return [
            Failed::class => 'handleFailed',
            Lockout::class => 'handleLockout',
            PasswordReset::class => 'handlePasswordReset',
        ];
    }
}
