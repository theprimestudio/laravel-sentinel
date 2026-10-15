@extends('laravel-sentinel::layouts.app')
@section('page_title')
    Vulnerabilities
@endsection
@section('content')
    @php
        $healthBadge = ['ok' => 'bg-success', 'warn' => 'bg-warning text-dark', 'fail' => 'bg-danger'];
        $runBadge = ['completed' => 'bg-success', 'partial' => 'bg-warning text-dark', 'failed' => 'bg-danger', 'running' => 'bg-info text-dark'];
    @endphp

    @if ($errors->any())
        <div class="alert alert-danger mt-3">
            @foreach ($errors->all() as $error)
                <div>{{ $error }}</div>
            @endforeach
        </div>
    @endif

    {{-- Severity summary --}}
    <div class="row g-3 mt-1">
        @foreach (['critical' => 'danger', 'high' => 'warning', 'medium' => 'info', 'low' => 'secondary'] as $sev => $color)
            <div class="col-6 col-lg-3">
                <a href="{{ route(config('security.admin.route_name_prefix', 'admin.').'vulnerabilities.index', ['severity' => $sev]) }}" class="text-decoration-none">
                    <div class="card border-start border-4 border-{{ $color }} h-100">
                        <div class="card-body py-3">
                            <div class="text-muted text-uppercase small fw-semibold">{{ ucfirst($sev) }} (unresolved)</div>
                            <div class="fs-3 fw-bold text-dark">{{ (int) ($counts[$sev] ?? 0) }}</div>
                        </div>
                    </div>
                </a>
            </div>
        @endforeach
    </div>

    {{-- Scanner health --}}
    <div class="card mt-3">
        <div class="card-header d-flex justify-content-between align-items-center">
            <strong><i class="cil-heart me-1"></i> Scanner health</strong>
            <span class="badge {{ $healthBadge[$health['overall']] }}">{{ strtoupper($health['overall']) }}</span>
        </div>
        <div class="card-body">
            <div class="table-responsive">
                <table class="table table-sm align-middle mb-2">
                    <tbody>
                        @foreach ($health['checks'] as $check)
                            <tr>
                                <td style="width: 220px;" class="fw-semibold">{{ $check['name'] }}</td>
                                <td style="width: 80px;"><span class="badge {{ $healthBadge[$check['status']] }}">{{ strtoupper($check['status']) }}</span></td>
                                <td>{{ $check['message'] }}</td>
                            </tr>
                        @endforeach
                        <tr>
                            <td class="fw-semibold">Inventory</td>
                            <td></td>
                            <td>{{ number_format($inventoryCount) }} files hashed (SHA-256) and tracked.</td>
                        </tr>
                    </tbody>
                </table>
            </div>
            @if (! empty($health['gaps']))
                <div class="alert alert-warning mb-0">
                    <strong>Coverage gaps (what the last scan did not cover):</strong>
                    <ul class="mb-0 mt-1">
                        @foreach (array_slice($health['gaps'], 0, 20) as $gap)
                            <li>{{ $gap }}</li>
                        @endforeach
                    </ul>
                </div>
            @endif
        </div>
    </div>

    {{-- Findings --}}
    <div class="card mt-3">
        <div class="card-header"><strong><i class="cil-bug me-1"></i> Findings</strong></div>
        <div class="card-body">
            <form method="GET" class="row g-2 mb-3">
                <div class="col-md-2">
                    <select name="status" class="form-select form-select-sm">
                        @foreach (['unresolved', 'open', 'acknowledged', 'quarantined', 'false_positive', 'resolved', 'all'] as $s)
                            <option value="{{ $s }}" @selected($status === $s)>{{ ucfirst(str_replace('_', ' ', $s)) }}</option>
                        @endforeach
                    </select>
                </div>
                <div class="col-md-2">
                    <select name="severity" class="form-select form-select-sm">
                        <option value="">Any severity</option>
                        @foreach (\App\Models\Security\Finding::SEVERITIES as $s)
                            <option value="{{ $s }}" @selected(($filters['severity'] ?? null) === $s)>{{ ucfirst($s) }}</option>
                        @endforeach
                    </select>
                </div>
                <div class="col-md-2">
                    <select name="category" class="form-select form-select-sm">
                        <option value="">Any category</option>
                        @foreach ($categories as $c)
                            <option value="{{ $c }}" @selected(($filters['category'] ?? null) === $c)>{{ \Illuminate\Support\Str::headline($c) }}</option>
                        @endforeach
                    </select>
                </div>
                <div class="col-md-4">
                    <input type="text" name="q" value="{{ $filters['q'] ?? '' }}" class="form-control form-control-sm" placeholder="Path or SHA-256">
                </div>
                <div class="col-md-2 d-grid">
                    <button class="btn btn-sm btn-primary">Filter</button>
                </div>
            </form>

            <div class="table-responsive">
                <table class="table table-bordered table-striped table-sm align-middle">
                    <thead class="table-light">
                        <tr>
                            <th>Severity</th>
                            <th>File</th>
                            <th>Detection</th>
                            <th>Confidence</th>
                            <th>Status</th>
                            <th>Last detected</th>
                            <th></th>
                        </tr>
                    </thead>
                    <tbody>
                        @forelse ($findings as $finding)
                            <tr>
                                <td><span class="badge {{ $finding->severityBadge() }}">{{ strtoupper($finding->severity) }}</span></td>
                                <td class="text-break" style="max-width: 420px;"><code>{{ $finding->path }}</code></td>
                                <td>
                                    <div class="small fw-semibold">{{ \Illuminate\Support\Str::headline($finding->category) }}</div>
                                    <div class="small text-muted">{{ $finding->rule }}</div>
                                </td>
                                <td>{{ $finding->confidence }}%</td>
                                <td><span class="badge bg-light text-dark border">{{ str_replace('_', ' ', $finding->status) }}</span></td>
                                <td class="small">{{ $finding->last_detected_at?->format('Y-m-d H:i') }}<br><span class="text-muted">{{ $finding->occurrences }}×</span></td>
                                <td>
                                    @can('view', $finding)
                                        <a href="{{ route(config('security.admin.route_name_prefix', 'admin.').'vulnerabilities.show', $finding) }}" class="btn btn-sm btn-primary">Details</a>
                                    @endcan
                                </td>
                            </tr>
                        @empty
                            <tr>
                                <td colspan="7" class="text-center text-muted">
                                    No findings for this filter.
                                    @if ($health['overall'] !== 'ok')
                                        <br><strong>Note:</strong> scanner health is not OK, so "no findings" is not proof the system is clean.
                                    @endif
                                </td>
                            </tr>
                        @endforelse
                    </tbody>
                </table>
            </div>
            {{ $findings->links() }}
        </div>
    </div>

    <div class="row g-3 mt-0 mb-4">
        {{-- Scan history --}}
        <div class="col-xl-7">
            <div class="card h-100">
                <div class="card-header"><strong><i class="cil-history me-1"></i> Scan history</strong></div>
                <div class="card-body table-responsive">
                    <table class="table table-sm align-middle">
                        <thead class="table-light">
                            <tr><th>#</th><th>Mode</th><th>Status</th><th>Started</th><th>Seen / Scanned</th><th>Findings</th><th>Errors</th><th>ClamAV</th></tr>
                        </thead>
                        <tbody>
                            @forelse ($runs as $run)
                                <tr>
                                    <td>{{ $run->id }}</td>
                                    <td>{{ $run->mode }}</td>
                                    <td><span class="badge {{ $runBadge[$run->status] ?? 'bg-secondary' }}">{{ $run->status }}</span></td>
                                    <td class="small">{{ $run->started_at?->format('Y-m-d H:i') }}</td>
                                    <td>{{ number_format($run->files_seen) }} / {{ number_format($run->files_scanned) }}</td>
                                    <td>{{ $run->findings_count }}</td>
                                    <td class="{{ $run->errors_count ? 'text-danger fw-bold' : '' }}">{{ $run->errors_count }}</td>
                                    <td class="small">{{ $run->engines['clamav'] ?? '—' }}</td>
                                </tr>
                            @empty
                                <tr><td colspan="8" class="text-center text-muted">No scans recorded yet. Run <code>php artisan security:scan --mode=full</code>.</td></tr>
                            @endforelse
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        {{-- Quarantine --}}
        <div class="col-xl-5">
            <div class="card h-100">
                <div class="card-header"><strong><i class="cil-lock-locked me-1"></i> Quarantine</strong></div>
                <div class="card-body table-responsive">
                    <table class="table table-sm align-middle">
                        <thead class="table-light"><tr><th>Original path</th><th>Status</th><th>When</th></tr></thead>
                        <tbody>
                            @forelse ($quarantined as $item)
                                <tr>
                                    <td class="text-break small">
                                        @if ($item->finding)
                                            @can('view', $item->finding)
                                                <a href="{{ route(config('security.admin.route_name_prefix', 'admin.').'vulnerabilities.show', $item->finding) }}"><code>{{ $item->original_path }}</code></a>
                                            @else
                                                <code>{{ $item->original_path }}</code>
                                            @endcan
                                        @else
                                            <code>{{ $item->original_path }}</code>
                                        @endif
                                    </td>
                                    <td><span class="badge {{ $item->status === 'quarantined' ? 'bg-dark' : 'bg-secondary' }}">{{ $item->status }}</span></td>
                                    <td class="small">{{ $item->quarantined_at?->format('Y-m-d H:i') }}</td>
                                </tr>
                            @empty
                                <tr><td colspan="3" class="text-center text-muted">Nothing quarantined.</td></tr>
                            @endforelse
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
@endsection
