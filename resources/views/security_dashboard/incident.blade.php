@extends('laravel-sentinel::layouts.app')
@section('page_title')
    Incident #{{ $incident->id }}
@endsection
@section('content')
    @if ($errors->any())
        <div class="alert alert-danger mt-3">@foreach ($errors->all() as $error)<div>{{ $error }}</div>@endforeach</div>
    @endif

    <div class="d-flex justify-content-between align-items-center mt-3 mb-2">
        <a href="{{ route(config('security.admin.route_name_prefix', 'admin.').'security-dashboard.index') }}" class="btn btn-sm btn-outline-secondary"><i class="cil-arrow-left"></i> Dashboard</a>
        <span class="badge fs-6 {{ \App\Models\Security\Incident::badgeFor($incident->severity) }}">{{ strtoupper($incident->severity) }}</span>
    </div>

    <div class="row g-3">
        <div class="col-xl-8">
            <div class="card">
                <div class="card-header"><strong>{{ $incident->title }}</strong></div>
                <div class="card-body">
                    <table class="table table-sm mb-0">
                        <tr><th style="width:180px;">Type</th><td>{{ \Illuminate\Support\Str::headline($incident->type) }}</td></tr>
                        <tr><th>Status</th><td>{{ str_replace('_', ' ', $incident->status) }}
                            @if ($incident->resolver) by {{ $incident->resolver->name }} at {{ $incident->resolved_at }} @endif</td></tr>
                        <tr><th>Assignee</th><td>{{ $incident->assignee?->name ?? '—' }}</td></tr>
                        <tr><th>Source IP</th><td>{{ $incident->source_ip ?? '—' }} <span class="text-muted small">(IP location is approximate; not proof of identity)</span></td></tr>
                        <tr><th>Events</th><td>{{ number_format($incident->event_count) }} stored
                            @if ($incident->suppressed_count) + {{ number_format($incident->suppressed_count) }} counted (flood control) @endif</td></tr>
                        <tr><th>First / last seen</th><td>{{ $incident->first_seen_at }} / {{ $incident->last_seen_at }}</td></tr>
                        <tr><th>Notified</th><td>{{ $incident->notified_at ?? 'no' }}</td></tr>
                    </table>
                </div>
            </div>

            <div class="card mt-3">
                <div class="card-header"><strong>Events</strong></div>
                <div class="card-body table-responsive">
                    <table class="table table-sm table-striped">
                        <thead class="table-light"><tr><th>Time</th><th>IP</th><th>Account</th><th>Method / route</th><th>Reason</th><th>Action</th><th>Context (redacted)</th></tr></thead>
                        <tbody>
                            @foreach ($events as $e)
                                <tr>
                                    <td class="small text-nowrap">{{ $e->occurred_at }}</td>
                                    <td class="small">{{ $e->source_ip }}</td>
                                    <td class="small">{{ $e->user?->name ?? '—' }}</td>
                                    <td class="small text-break">{{ $e->method }} {{ $e->route }}</td>
                                    <td class="small text-break">{{ $e->reason }}</td>
                                    <td class="small">{{ $e->action }}</td>
                                    <td class="small text-break" style="max-width:280px;"><code>{{ json_encode($e->context, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) }}</code></td>
                                </tr>
                            @endforeach
                        </tbody>
                    </table>
                    {{ $events->links() }}
                </div>
            </div>
        </div>

        <div class="col-xl-4">
            @can('admin_system_security-incident-manage')
                <div class="card">
                    <div class="card-header"><strong>Manage</strong></div>
                    <div class="card-body">
                        <form method="POST" action="{{ route(config('security.admin.route_name_prefix', 'admin.').'security-dashboard.incident.update', $incident) }}">
                            @csrf
                            <label class="form-label small mb-0">Status</label>
                            <select name="status" class="form-select form-select-sm mb-2">
                                @foreach (\App\Models\Security\Incident::STATUSES as $s)
                                    <option value="{{ $s }}" @selected($incident->status === $s)>{{ ucfirst(str_replace('_', ' ', $s)) }}</option>
                                @endforeach
                            </select>
                            <label class="form-label small mb-0">Assign to</label>
                            <select name="assigned_to" class="form-select form-select-sm mb-2">
                                <option value="">— unassigned —</option>
                                @foreach ($assignees as $u)
                                    <option value="{{ $u->id }}" @selected($incident->assigned_to === $u->id)>{{ $u->name }}</option>
                                @endforeach
                            </select>
                            <label class="form-label small mb-0">Investigation note</label>
                            <textarea name="note" rows="4" class="form-control form-control-sm mb-2" maxlength="5000" placeholder="Findings, actions taken (required for false positive)"></textarea>
                            <button class="btn btn-sm btn-primary w-100">Save</button>
                        </form>
                    </div>
                </div>
            @endcan

            <div class="card mt-3">
                <div class="card-header"><strong>History</strong></div>
                <div class="card-body small">
                    @foreach ($incident->notes as $n)
                        <div class="border-bottom pb-1 mb-1">
                            <div class="text-muted">{{ $n->created_at }} · {{ $n->user?->name ?? 'system' }} · {{ str_replace('_', ' ', $n->action) }}</div>
                            @if ($n->note)<div style="white-space: pre-wrap;">{{ $n->note }}</div>@endif
                            @if ($n->meta)<code>{{ json_encode($n->meta, JSON_UNESCAPED_SLASHES) }}</code>@endif
                        </div>
                    @endforeach
                </div>
            </div>
        </div>
    </div>
@endsection
