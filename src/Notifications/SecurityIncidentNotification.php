<?php

namespace ThePrimeStudio\LaravelSentinel\Notifications;

use ThePrimeStudio\LaravelSentinel\Models\Incident;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;
use Illuminate\Support\Str;

/**
 * Queued alert for new/escalated incidents. Contains no request payloads, credentials or
 * session data — only the incident summary and a link that requires login + permission.
 */
class SecurityIncidentNotification extends Notification implements ShouldQueue
{
    use Queueable;

    public int $tries = 3;

    public array $backoff = [60, 300];

    public function __construct(public Incident $incident) {}

    public function via(object $notifiable): array
    {
        return ['mail'];
    }

    public function toMail(object $notifiable): MailMessage
    {
        $i = $this->incident;

        return (new MailMessage)
            ->subject('['.strtoupper($i->severity).'] Security incident #'.$i->id.' on '.config('app.name'))
            ->line('Type: '.Str::headline($i->type))
            ->line('Summary: '.Str::limit($i->title, 200))
            ->line('Source IP: '.($i->source_ip ?? 'n/a').' (IP-based location is approximate and not proof of identity).')
            ->line('First seen: '.$i->first_seen_at?->toDateTimeString().' · events: '.$i->event_count)
            ->action('Open incident', route(config('security.admin.route_name_prefix', 'admin.').'security-dashboard.incident', $i))
            ->line('Heuristic detections are suspicions that need review, not confirmed compromise.');
    }
}
