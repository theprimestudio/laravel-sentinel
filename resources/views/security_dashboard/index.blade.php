@extends('laravel-sentinel::layouts.app')
@section('page_title')
    Security Dashboard
@endsection
@section('content')
    @php
        $badge = ['ok' => 'bg-success', 'warn' => 'bg-warning text-dark', 'fail' => 'bg-danger'];
        $q = array_filter([
            'from' => $filters['from']->toDateString(), 'to' => $filters['to']->toDateString(),
            'severity' => $filters['severity'], 'type' => $filters['type'], 'ip' => $filters['ip'], 'q' => $filters['q'],
        ]);
        $cardDefs = [
            ['total', 'Total events', 'dark', 'cil-list'],
            ['critical', 'Critical', 'danger', 'cil-warning'],
            ['high', 'High', 'warning', 'cil-warning'],
            ['medium', 'Medium', 'info', 'cil-info'],
            ['low', 'Low', 'secondary', 'cil-info'],
            ['blocked', 'Blocked requests', 'danger', 'cil-ban'],
            ['failed_logins', 'Failed logins / lockouts', 'warning', 'cil-user-x'],
            ['suspicious_ips', 'Suspicious IPs', 'warning', 'cil-globe-alt'],
            ['malicious_uploads', 'Malicious upload attempts', 'danger', 'cil-cloud-upload'],
            ['stored_xss', 'Stored-XSS detections', 'danger', 'cil-code'],
            ['exploit_attempts', 'Exploit attempts', 'danger', 'cil-bug'],
            ['integrity_changes', 'Integrity changes (open)', 'warning', 'cil-file'],
            ['malware_confirmed', 'Malware — signature confirmed (open)', 'danger', 'cil-shield-alt'],
            ['malware_suspected', 'Suspicious files — heuristic (open)', 'warning', 'cil-magnifying-glass'],
            ['affected_users', 'Affected accounts', 'info', 'cil-people'],
            ['affected_routes', 'Affected routes', 'info', 'cil-sitemap'],
            ['affected_files', 'Affected files (open)', 'info', 'cil-folder-open'],
            ['incidents_open', 'Unresolved incidents', 'danger', 'cil-bell'],
            ['incidents_resolved', 'Resolved incidents (range)', 'success', 'cil-check-circle'],
        ];
    @endphp

    {{-- Filters --}}
    <form method="GET" class="card mt-3">
        <div class="card-body row g-2 align-items-end">
            <div class="col-6 col-md-2"><label class="form-label small mb-0">From</label>
                <input type="date" name="from" value="{{ $filters['from']->toDateString() }}" class="form-control form-control-sm"></div>
            <div class="col-6 col-md-2"><label class="form-label small mb-0">To</label>
                <input type="date" name="to" value="{{ $filters['to']->toDateString() }}" class="form-control form-control-sm"></div>
            <div class="col-6 col-md-2"><label class="form-label small mb-0">Severity</label>
                <select name="severity" class="form-select form-select-sm"><option value="">All</option>
                    @foreach (['critical', 'high', 'medium', 'low'] as $s)
                        <option value="{{ $s }}" @selected($filters['severity'] === $s)>{{ ucfirst($s) }}</option>
                    @endforeach
                </select></div>
            <div class="col-6 col-md-2"><label class="form-label small mb-0">Type</label>
                <select name="type" class="form-select form-select-sm"><option value="">All</option>
                    @foreach ($types as $t)
                        <option value="{{ $t }}" @selected($filters['type'] === $t)>{{ \Illuminate\Support\Str::headline($t) }}</option>
                    @endforeach
                </select></div>
            <div class="col-6 col-md-1"><label class="form-label small mb-0">IP</label>
                <input type="text" name="ip" value="{{ $filters['ip'] }}" class="form-control form-control-sm"></div>
            <div class="col-6 col-md-2"><label class="form-label small mb-0">Search</label>
                <input type="text" name="q" value="{{ $filters['q'] }}" class="form-control form-control-sm" placeholder="reason, route, path"></div>
            <div class="col-12 col-md-1 d-flex gap-1">
                <button class="btn btn-sm btn-primary flex-fill">Apply</button>
            </div>
        </div>
    </form>

    {{-- Cards --}}
    <div class="row g-2 mt-1" id="sec-cards">
        @foreach ($cardDefs as [$key, $label, $color, $icon])
            <div class="col-6 col-md-4 col-xl-2">
                <div class="card border-start border-4 border-{{ $color }} h-100">
                    <div class="card-body py-2 px-3">
                        <div class="text-muted small text-truncate" title="{{ $label }}"><i class="{{ $icon }} me-1"></i>{{ $label }}</div>
                        <div class="fs-4 fw-bold" data-card="{{ $key }}">{{ number_format($cards[$key]) }}</div>
                    </div>
                </div>
            </div>
        @endforeach
    </div>
    @if ($cards['suppressed'] > 0)
        <div class="small text-muted mt-1">Includes {{ number_format($cards['suppressed']) }} repeated events counted but not stored individually (flood control).</div>
    @endif

    <div class="row g-3 mt-0">
        <div class="col-xl-8">
            <div class="card h-100">
                <div class="card-header"><strong>Events per day by severity</strong></div>
                <div class="card-body"><canvas id="sec-chart" height="110"></canvas></div>
            </div>
        </div>
        <div class="col-xl-4">
            <div class="card h-100">
                <div class="card-header d-flex justify-content-between">
                    <strong>Monitoring health</strong>
                    <span class="badge {{ $badge[$health['overall']] }}">{{ strtoupper($health['overall']) }}</span>
                </div>
                <div class="card-body small" style="max-height: 320px; overflow:auto;">
                    @foreach ($health['checks'] as $c)
                        <div class="d-flex gap-2 mb-1">
                            <span class="badge {{ $badge[$c['status']] }} align-self-start">{{ strtoupper($c['status']) }}</span>
                            <div><strong>{{ $c['name'] }}</strong> — {{ $c['message'] }}</div>
                        </div>
                    @endforeach
                    @if ($health['overall'] !== 'ok')
                        <div class="alert alert-warning py-1 px-2 mt-2 mb-0">While health is not OK, low numbers here do not prove the site is safe.</div>
                    @endif
                </div>
            </div>
        </div>
    </div>

    {{-- Incidents --}}
    <div class="card mt-3">
        <div class="card-header"><strong>Unresolved incidents</strong> <span class="text-muted small">(repeated events are grouped)</span></div>
        <div class="card-body table-responsive">
            <table class="table table-sm align-middle">
                <thead class="table-light"><tr><th>#</th><th>Severity</th><th>Incident</th><th>Source IP</th><th>Events</th><th>Last seen</th><th>Status</th><th>Assignee</th></tr></thead>
                <tbody>
                    @forelse ($incidents as $i)
                        <tr>
                            <td><a href="{{ route(config('security.admin.route_name_prefix', 'admin.').'security-dashboard.incident', $i) }}">{{ $i->id }}</a></td>
                            <td><span class="badge {{ \App\Models\Security\Incident::badgeFor($i->severity) }}">{{ strtoupper($i->severity) }}</span></td>
                            <td class="text-break" style="max-width:420px;"><a href="{{ route(config('security.admin.route_name_prefix', 'admin.').'security-dashboard.incident', $i) }}">{{ $i->title }}</a></td>
                            <td>{{ $i->source_ip }}</td>
                            <td>{{ number_format($i->event_count + $i->suppressed_count) }}</td>
                            <td class="small">{{ $i->last_seen_at?->diffForHumans() }}</td>
                            <td>{{ str_replace('_', ' ', $i->status) }}</td>
                            <td>{{ $i->assignee?->name ?? '—' }}</td>
                        </tr>
                    @empty
                        <tr><td colspan="8" class="text-center text-muted">No unresolved incidents.</td></tr>
                    @endforelse
                </tbody>
            </table>
        </div>
    </div>

    {{-- Live event stream --}}
    <div class="card mt-3 mb-4">
        <div class="card-header d-flex justify-content-between align-items-center">
            <strong>Events <span class="badge bg-success ms-1" id="sec-live">LIVE</span></strong>
            @can('admin_system_security-dashboard-export')
                <a class="btn btn-sm btn-outline-secondary" href="{{ route(config('security.admin.route_name_prefix', 'admin.').'security-dashboard.export', $q) }}"><i class="cil-cloud-download"></i> Export CSV</a>
            @endcan
        </div>
        <div class="card-body table-responsive">
            <table class="table table-sm table-striped align-middle">
                <thead class="table-light"><tr><th>Time</th><th>Severity</th><th>Type</th><th>Source IP</th><th>Account</th><th>Route</th><th>Detection reason</th><th>Action</th><th>Incident</th></tr></thead>
                <tbody id="sec-events">
                    @forelse ($events as $e)
                        <tr>
                            <td class="small text-nowrap">{{ $e->occurred_at?->format('Y-m-d H:i:s') }}</td>
                            <td><span class="badge {{ $e->severityBadge() }}">{{ strtoupper($e->severity) }}</span></td>
                            <td class="small">{{ \Illuminate\Support\Str::headline($e->type) }}</td>
                            <td class="small"><a href="{{ route(config('security.admin.route_name_prefix', 'admin.').'security-dashboard.index', ['ip' => $e->source_ip] + $q) }}">{{ $e->source_ip }}</a></td>
                            <td class="small">{{ $e->user?->name ?? '—' }}</td>
                            <td class="small text-break">{{ $e->route }}</td>
                            <td class="small text-break" style="max-width:360px;">{{ \Illuminate\Support\Str::limit($e->reason, 160) }}</td>
                            <td class="small">{{ $e->action }}</td>
                            <td class="small">@if ($e->incident_id)<a href="{{ route(config('security.admin.route_name_prefix', 'admin.').'security-dashboard.incident', $e->incident_id) }}">#{{ $e->incident_id }}</a>@endif</td>
                        </tr>
                    @empty
                        <tr id="sec-empty"><td colspan="9" class="text-center text-muted">No events for this filter.</td></tr>
                    @endforelse
                </tbody>
            </table>
            {{ $events->links() }}
        </div>
    </div>
@endsection

@push('footer-scripts')
    <script src="{{ asset_v('admin/coreui/vendors/chart.js/js/chart.min.js') }}"></script>
    <script>
        (function () {
            var chartData = @json($chart);
            var colors = { critical: '#e55353', high: '#f9b115', medium: '#39f', low: '#9da5b1' };
            var ctx = document.getElementById('sec-chart');
            if (ctx && window.Chart) {
                new Chart(ctx, {
                    type: 'bar',
                    data: {
                        labels: chartData.labels,
                        datasets: Object.keys(chartData.series).map(function (k) {
                            return { label: k, data: chartData.series[k], backgroundColor: colors[k], stack: 's' };
                        })
                    },
                    options: { responsive: true, scales: { x: { stacked: true }, y: { stacked: true, beginAtZero: true, ticks: { precision: 0 } } } }
                });
            }

            // Live updates: authenticated polling (only on page 1, when the filtered range includes now).
            var onFirstPage = {{ $events->currentPage() === 1 ? 'true' : 'false' }};
            var includesNow = {{ $filters['to']->isFuture() || $filters['to']->isToday() ? 'true' : 'false' }};
            var live = document.getElementById('sec-live');
            if (!onFirstPage || !includesNow || !window.fetch) { live.className = 'badge bg-secondary ms-1'; live.textContent = 'PAUSED'; return; }

            var lastId = {{ (int) $lastEventId }};
            var feedUrl = @json(route(config('security.admin.route_name_prefix', 'admin.').'security-dashboard.feed', $q));
            var badgeFor = { critical: 'bg-danger', high: 'bg-warning text-dark', medium: 'bg-info text-dark', low: 'bg-secondary' };
            var tbody = document.getElementById('sec-events');

            function cell(text, cls) { var td = document.createElement('td'); td.className = 'small ' + (cls || ''); td.textContent = text == null ? '' : text; return td; }

            function addRow(e) {
                var tr = document.createElement('tr');
                tr.className = 'table-warning';
                tr.appendChild(cell(e.time, 'text-nowrap'));
                var sev = document.createElement('td'); var b = document.createElement('span');
                b.className = 'badge ' + (badgeFor[e.severity] || 'bg-secondary'); b.textContent = String(e.severity).toUpperCase(); sev.appendChild(b); tr.appendChild(sev);
                tr.appendChild(cell(e.type)); tr.appendChild(cell(e.ip)); tr.appendChild(cell(e.user || '—'));
                tr.appendChild(cell(e.route, 'text-break')); tr.appendChild(cell(e.reason, 'text-break')); tr.appendChild(cell(e.action));
                var inc = document.createElement('td'); inc.className = 'small';
                if (e.incident_url) { var a = document.createElement('a'); a.href = e.incident_url; a.textContent = '#' + e.incident_id; inc.appendChild(a); }
                tr.appendChild(inc);
                var empty = document.getElementById('sec-empty'); if (empty) empty.remove();
                tbody.insertBefore(tr, tbody.firstChild);
                while (tbody.rows.length > 100) tbody.deleteRow(-1);
            }

            function poll() {
                if (document.hidden) return;
                var url = feedUrl + (feedUrl.indexOf('?') === -1 ? '?' : '&') + 'after=' + lastId;
                fetch(url, { headers: { 'Accept': 'application/json', 'X-Requested-With': 'XMLHttpRequest' }, credentials: 'same-origin' })
                    .then(function (r) { if (!r.ok) throw new Error(r.status); return r.json(); })
                    .then(function (d) {
                        live.className = 'badge bg-success ms-1'; live.textContent = 'LIVE';
                        d.events.slice().reverse().forEach(addRow);
                        lastId = Math.max(lastId, d.last_id || 0);
                        Object.keys(d.cards).forEach(function (k) {
                            var el = document.querySelector('[data-card="' + k + '"]');
                            if (el) el.textContent = Number(d.cards[k]).toLocaleString();
                        });
                    })
                    .catch(function () { live.className = 'badge bg-danger ms-1'; live.textContent = 'OFFLINE'; });
            }
            setInterval(poll, {{ max(10, (int) config('security.events.dashboard_poll_seconds', 15)) }} * 1000);
        })();
    </script>
@endpush
