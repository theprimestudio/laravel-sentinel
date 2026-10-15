<?php

namespace ThePrimeStudio\LaravelSentinel\Http\Controllers;

use Illuminate\Routing\Controller;

use ThePrimeStudio\LaravelSentinel\Console\SecurityMonitorCommand;

use ThePrimeStudio\LaravelSentinel\Models\Finding;
use ThePrimeStudio\LaravelSentinel\Models\Incident;
use ThePrimeStudio\LaravelSentinel\Models\IncidentNote;
use ThePrimeStudio\LaravelSentinel\Models\SecurityEvent;
// Host User decoupled
use ThePrimeStudio\LaravelSentinel\Services\ScannerHealth;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Session;
use Illuminate\Support\Str;
use Illuminate\View\View;
use Symfony\Component\HttpFoundation\StreamedResponse;

class SecurityDashboardController extends Controller
{
    public const EVENT_TYPES = [
        'exploit_attempt', 'blocked_request', 'failed_login', 'lockout', 'brute_force', 'credential_stuffing',
        'malicious_upload', 'stored_xss', 'integrity_change', 'malware_suspected', 'malware_confirmed',
        'file_anomaly', 'scanner_health', 'notification_failure', 'log_tamper', 'content_restored',
        'security_txt_change', 'password_reset', 'report_export',
    ];

    public function __construct()
    {
        
        if (config('security.admin.permissions_enabled', true)) {
            $this->middleware('permission:admin_system_security-dashboard-view', ['only' => ['index', 'feed', 'incident']]);
            
            
        }
        
        
    }

    public function index(Request $request, ScannerHealth $health): View
    {
        $filters = $this->filters($request);
        $events = $this->eventQuery($filters)->with('user:id,name')->latest('id')->paginate(25)->withQueryString();

        return view('laravel-sentinel::security_dashboard.index', [
            'filters' => $filters,
            'events' => $events,
            'cards' => $this->cards($filters),
            'chart' => $this->chart($filters),
            'incidents' => Incident::unresolved()->with('assignee:id,name')
                ->orderByRaw("CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END")
                ->latest('last_seen_at')->limit(15)->get(),
            'health' => $this->healthSummary($health),
            'types' => self::EVENT_TYPES,
            'lastEventId' => (int) SecurityEvent::max('id'),
        ]);
    }

    /** Authenticated polling for live updates (no broadcasting infrastructure is configured). */
    public function feed(Request $request): JsonResponse
    {
        $after = max(0, (int) $request->query('after', 0));
        $filters = $this->filters($request);

        $new = $this->eventQuery($filters)->with('user:id,name')->where('id', '>', $after)->latest('id')->limit(50)->get()
            ->map(fn (SecurityEvent $e) => $this->eventRow($e));

        return response()->json([
            'events' => $new,
            'last_id' => (int) ($new->first()['id'] ?? $after),
            'cards' => $this->cards($filters),
        ])->header('Cache-Control', 'no-store');
    }

    /** CSV export of the filtered events (redacted context only; formula-injection safe). */
    public function export(Request $request): StreamedResponse
    {
        $filters = $this->filters($request);
        app(\ThePrimeStudio\LaravelSentinel\Services\SecurityEventRecorder::class)->record('report_export', 'low', 'Security events exported', ['filters' => $filters]);

        return response()->streamDownload(function () use ($filters) {
            $out = fopen('php://output', 'w');
            fputcsv($out, ['id', 'occurred_at', 'severity', 'type', 'source_ip', 'user', 'method', 'route', 'reason', 'action', 'incident_id', 'hash']);
            $this->eventQuery($filters)->with('user:id,name')->orderBy('id')->chunk(1000, function ($rows) use ($out) {
                foreach ($rows as $e) {
                    fputcsv($out, array_map([self::class, 'csvSafe'], [
                        $e->id, $e->occurred_at, $e->severity, $e->type, $e->source_ip, $e->user?->name, $e->method,
                        $e->route, $e->reason, $e->action, $e->incident_id, $e->hash,
                    ]));
                }
            });
            fclose($out);
        }, 'security-events-'.now()->format('Ymd-His').'.csv', ['Content-Type' => 'text/csv; charset=UTF-8']);
    }

    public function incident(Incident $incident): View
    {
        $incident->load(['notes.user:id,name', 'assignee:id,name', 'resolver:id,name']);

        return view('laravel-sentinel::security_dashboard.incident', [
            'incident' => $incident,
            'events' => $incident->events()->with('user:id,name')->paginate(25),
            'assignees' => User::permission('admin_system_security-incident-manage')->orderBy('name')->get(['id', 'name']),
        ]);
    }

    public function updateIncident(Request $request, Incident $incident): RedirectResponse
    {
        $data = $request->validate([
            'status' => 'nullable|in:'.implode(',', Incident::STATUSES),
            'assigned_to' => 'nullable|integer|exists:users,id',
            'note' => 'nullable|string|max:5000',
        ]);
        if (($data['status'] ?? null) === 'false_positive' && empty($data['note'])) {
            return back()->withErrors(['note' => 'Explain why this is a false positive.']);
        }

        DB::transaction(function () use ($incident, $data, $request) {
            $user = $request->user();
            if (! empty($data['status']) && $data['status'] !== $incident->status) {
                $from = $incident->status;
                $closed = in_array($data['status'], ['resolved', 'false_positive'], true);
                $incident->update(['status' => $data['status'], 'resolved_by' => $closed ? $user->id : null, 'resolved_at' => $closed ? now() : null]);
                IncidentNote::create(['incident_id' => $incident->id, 'user_id' => $user->id, 'action' => 'status_changed', 'note' => $data['note'] ?? null, 'meta' => ['from' => $from, 'to' => $data['status']], 'ip' => $request->ip(), 'created_at' => now()]);
                $data['note'] = null; // already stored with the status change
            }
            if (array_key_exists('assigned_to', $data) && (int) $data['assigned_to'] !== (int) $incident->assigned_to) {
                $assignee = $data['assigned_to'] ? User::find($data['assigned_to']) : null;
                abort_if($assignee && ! $assignee->can('admin_system_security-incident-manage'), 422, 'Assignee must be allowed to manage incidents.');
                $incident->update(['assigned_to' => $assignee?->id]);
                IncidentNote::create(['incident_id' => $incident->id, 'user_id' => $user->id, 'action' => 'assigned', 'meta' => ['to' => $assignee?->id], 'ip' => $request->ip(), 'created_at' => now()]);
            }
            if (! empty($data['note'])) {
                IncidentNote::create(['incident_id' => $incident->id, 'user_id' => $user->id, 'action' => 'note', 'note' => $data['note'], 'ip' => $request->ip(), 'created_at' => now()]);
            }
        });

        Session::flash('messages', [['message' => 'Incident updated.', 'message_type' => 'success']]);

        return back();
    }

    /** @return array{from: Carbon, to: Carbon, severity: ?string, type: ?string, ip: ?string, q: ?string} */
    protected function filters(Request $request): array
    {
        $v = $request->validate([
            'from' => 'nullable|date', 'to' => 'nullable|date',
            'severity' => 'nullable|in:critical,high,medium,low',
            'type' => 'nullable|in:'.implode(',', self::EVENT_TYPES),
            'ip' => 'nullable|ip', 'q' => 'nullable|string|max:200',
        ]);
        $from = isset($v['from']) ? Carbon::parse($v['from'])->startOfDay() : now()->subDays(6)->startOfDay();
        $to = isset($v['to']) ? Carbon::parse($v['to'])->endOfDay() : now()->endOfDay();
        if ($from->gt($to)) {
            [$from, $to] = [$to->copy()->startOfDay(), $from->copy()->endOfDay()];
        }
        if ($from->diffInDays($to) > 366) {
            $from = $to->copy()->subDays(366)->startOfDay();
        }

        return ['from' => $from, 'to' => $to, 'severity' => $v['severity'] ?? null, 'type' => $v['type'] ?? null, 'ip' => $v['ip'] ?? null, 'q' => $v['q'] ?? null];
    }

    protected function eventQuery(array $f): Builder
    {
        return SecurityEvent::query()
            ->whereBetween('occurred_at', [$f['from'], $f['to']])
            ->when($f['severity'], fn ($q, $s) => $q->where('severity', $s))
            ->when($f['type'], fn ($q, $t) => $q->where('type', $t))
            ->when($f['ip'], fn ($q, $ip) => $q->where('source_ip', $ip))
            ->when($f['q'], function ($q, $term) {
                $like = '%'.addcslashes($term, '%_\\').'%';
                $q->where(fn ($w) => $w->where('reason', 'like', $like)->orWhere('route', 'like', $like)->orWhere('path', 'like', $like));
            });
    }

    protected function cards(array $f): array
    {
        $base = fn () => SecurityEvent::query()->whereBetween('occurred_at', [$f['from'], $f['to']]);
        $bySeverity = $base()->select('severity', DB::raw('count(*) as c'))->groupBy('severity')->pluck('c', 'severity');
        $byType = $base()->select('type', DB::raw('count(*) as c'))->groupBy('type')->pluck('c', 'type');
        $suppressed = (int) Incident::whereBetween('last_seen_at', [$f['from'], $f['to']])->sum('suppressed_count');

        return [
            'total' => (int) $bySeverity->sum() + $suppressed,
            'critical' => (int) ($bySeverity['critical'] ?? 0),
            'high' => (int) ($bySeverity['high'] ?? 0),
            'medium' => (int) ($bySeverity['medium'] ?? 0),
            'low' => (int) ($bySeverity['low'] ?? 0),
            'suppressed' => $suppressed,
            'blocked' => (int) $base()->where('action', 'blocked')->count(),
            'failed_logins' => (int) (($byType['failed_login'] ?? 0) + ($byType['lockout'] ?? 0)),
            'suspicious_ips' => (int) $base()->whereNotNull('source_ip')->where('source_ip', '!=', '127.0.0.1')
                ->where(fn ($q) => $q->whereIn('severity', ['critical', 'high'])->orWhereIn('type', ['exploit_attempt', 'brute_force', 'credential_stuffing', 'malicious_upload']))
                ->distinct()->count('source_ip'),
            'malicious_uploads' => (int) ($byType['malicious_upload'] ?? 0),
            'stored_xss' => (int) ($byType['stored_xss'] ?? 0),
            'stored_xss_open' => (int) Finding::unresolved()->where('category', 'stored_xss')->count(),
            'integrity_changes' => (int) Finding::unresolved()->where('category', 'integrity')->count(),
            'malware_suspected' => (int) Finding::unresolved()->whereNotIn('category', ['integrity', 'stored_xss', 'suspicious_content', 'malware'])->count(),
            'malware_confirmed' => (int) Finding::unresolved()->where('category', 'malware')->count(),
            'exploit_attempts' => (int) ($byType['exploit_attempt'] ?? 0),
            'affected_users' => (int) $base()->whereNotNull('user_id')->whereIn('severity', ['critical', 'high', 'medium'])->distinct()->count('user_id'),
            'affected_routes' => (int) $base()->whereNotNull('route')->whereIn('severity', ['critical', 'high', 'medium'])->distinct()->count('route'),
            'affected_files' => (int) Finding::unresolved()->where('path', 'not like', 'db://%')->distinct()->count('path'),
            'incidents_open' => (int) Incident::unresolved()->count(),
            'incidents_resolved' => (int) Incident::whereIn('status', ['resolved', 'false_positive'])->whereBetween('resolved_at', [$f['from'], $f['to']])->count(),
        ];
    }

    protected function chart(array $f): array
    {
        $rows = SecurityEvent::query()->whereBetween('occurred_at', [$f['from'], $f['to']])
            ->get(['occurred_at', 'severity'])
            ->groupBy(fn ($e) => $e->occurred_at->format('Y-m-d'));

        $labels = [];
        $series = ['critical' => [], 'high' => [], 'medium' => [], 'low' => []];
        for ($d = $f['from']->copy(); $d->lte($f['to']); $d->addDay()) {
            $key = $d->format('Y-m-d');
            $labels[] = $d->format('M d');
            $day = $rows->get($key, collect());
            foreach ($series as $sev => $_) {
                $series[$sev][] = $day->where('severity', $sev)->count();
            }
        }

        return ['labels' => $labels, 'series' => $series];
    }

    protected function healthSummary(ScannerHealth $health): array
    {
        $report = $health->report();
        $monitor = Cache::get(SecurityMonitorCommand::STATUS_KEY);
        $add = function (string $name, string $status, string $message) use (&$report) {
            $report['checks'][] = compact('name', 'status', 'message');
        };

        if (! $monitor) {
            $add('Security monitor', 'fail', 'security:monitor has never run — is the scheduler (cron) installed?');
        } else {
            $age = now()->timestamp - (int) $monitor['ran_at'];
            $add('Security monitor', $age > 900 ? 'fail' : 'ok', 'Last run '.now()->subSeconds($age)->diffForHumans().'.');
            $chain = $monitor['chain'] ?? null;
            if ($chain) {
                $add('Event log integrity', $chain['ok'] ? 'ok' : 'fail', $chain['ok'] ? "Hash chain verified ({$chain['checked']} recent events)." : "Hash chain BROKEN at event #{$chain['broken_at']} — events were altered outside the app.");
            }
            $im = $monitor['imunify']['state'] ?? 'skipped';
            $add('Imunify360', $im === 'ok' ? 'ok' : ($im === 'error' ? 'warn' : 'ok'), match ($im) {
                'ok' => 'Agent detected; detections imported.',
                'error' => 'Agent present but query failed.',
                'not_installed' => 'Not installed (optional).',
                default => 'Not checked.',
            });
        }

        $failure = Cache::get('security:notifications:last_failure');
        if (! config('security.notifications.mail_to')) {
            $add('Alert notifications', 'warn', 'SECURITY_ALERT_EMAILS is not set — incidents are only visible on this dashboard.');
        } elseif ($failure && now()->timestamp - $failure['at'] < 86400) {
            $add('Alert notifications', 'fail', 'Last delivery failed: '.$failure['error']);
        } else {
            $add('Alert notifications', 'ok', 'Mail alerts configured (min severity: '.config('security.notifications.min_severity').').');
        }

        $statuses = array_column($report['checks'], 'status');
        $report['overall'] = in_array('fail', $statuses, true) ? 'fail' : (in_array('warn', $statuses, true) ? 'warn' : 'ok');

        return $report;
    }

    /** @return array<string, mixed> */
    protected function eventRow(SecurityEvent $e): array
    {
        return [
            'id' => $e->id,
            'time' => $e->occurred_at?->format('Y-m-d H:i:s'),
            'severity' => $e->severity,
            'type' => Str::headline($e->type),
            'ip' => $e->source_ip,
            'user' => $e->user?->name,
            'route' => $e->route,
            'reason' => Str::limit($e->reason, 160),
            'action' => $e->action,
            'incident_id' => $e->incident_id,
            'incident_url' => $e->incident_id ? route('admin.security-dashboard.incident', $e->incident_id) : null,
        ];
    }

    /** Neutralise spreadsheet formula injection in exported cells. */
    public static function csvSafe(mixed $value): string
    {
        $value = (string) $value;

        return preg_match('/^[=+\-@\t\r]/', $value) ? "'".$value : $value;
    }
}
