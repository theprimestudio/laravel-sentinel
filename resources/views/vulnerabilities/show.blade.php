@extends('laravel-sentinel::layouts.app')
@section('page_title')
    Finding #{{ $finding->id }}
@endsection
@section('content')
    @if ($errors->any())
        <div class="alert alert-danger mt-3">
            @foreach ($errors->all() as $error)
                <div>{{ $error }}</div>
            @endforeach
        </div>
    @endif

    <div class="d-flex justify-content-between align-items-center mt-3 mb-2">
        <a href="{{ route(config('security.admin.route_name_prefix', 'admin.').'vulnerabilities.index') }}" class="btn btn-sm btn-outline-secondary"><i class="cil-arrow-left"></i> All findings</a>
        <span class="badge fs-6 {{ $finding->severityBadge() }}">{{ strtoupper($finding->severity) }} · {{ $finding->confidence }}% confidence</span>
    </div>

    <div class="row g-3">
        <div class="col-xl-8">
            <div class="card">
                <div class="card-header"><strong>Detection</strong></div>
                <div class="card-body">
                    <table class="table table-sm mb-3">
                        <tbody>
                            <tr><th style="width: 180px;">File</th><td class="text-break"><code>{{ $finding->path }}</code></td></tr>
                            <tr><th>SHA-256</th><td class="text-break"><code>{{ $finding->sha256 ?? '—' }}</code></td></tr>
                            <tr><th>Category / rule</th><td>{{ \Illuminate\Support\Str::headline($finding->category) }} — <code>{{ $finding->rule }}</code></td></tr>
                            <tr><th>Detection basis</th><td><span class="badge {{ str_starts_with($finding->detectionBasis(), 'Confirmed') ? 'bg-danger' : 'bg-light text-dark border' }}">{{ $finding->detectionBasis() }}</span></td></tr>
                            <tr><th>Status</th><td>{{ str_replace('_', ' ', $finding->status) }}
                                @if ($finding->resolver) by {{ $finding->resolver->name }} at {{ $finding->resolved_at }} @endif</td></tr>
                            <tr><th>First / last seen</th><td>{{ $finding->first_detected_at }} / {{ $finding->last_detected_at }} ({{ $finding->occurrences }}×)</td></tr>
                            <tr><th>Scan run</th><td>#{{ $finding->scan_run_id ?? '—' }}</td></tr>
                            @if ($inventory)
                                <tr><th>File metadata</th><td class="small">
                                    size {{ number_format($inventory->size) }} B · perms {{ $inventory->perms }} ·
                                    mtime {{ $inventory->mtime ? \Illuminate\Support\Carbon::createFromTimestamp($inventory->mtime)->toDateTimeString() : '—' }} ·
                                    first seen {{ $inventory->first_seen_at }}
                                    @if ($inventory->baseline_sha256 && $inventory->baseline_sha256 !== $finding->sha256)
                                        <br>baseline <code>{{ $inventory->baseline_sha256 }}</code>
                                    @endif
                                </td></tr>
                            @endif
                        </tbody>
                    </table>

                    <h6>Why it was flagged</h6>
                    <ul>
                        @foreach ((array) $finding->reasons as $reason)
                            <li>{{ $reason }}</li>
                        @endforeach
                    </ul>

                    @if ($finding->evidence)
                        <h6>Evidence excerpt <small class="text-muted">(inert text, truncated — never executed)</small></h6>
                        <pre class="bg-light border p-2 small text-break" style="white-space: pre-wrap; max-height: 260px; overflow:auto;">{{ $finding->evidence }}</pre>
                    @endif

                    <h6>Remediation</h6>
                    <p class="mb-0">{{ $finding->remediation }}</p>
                </div>
            </div>

            <div class="card mt-3">
                <div class="card-header"><strong>Audit history</strong></div>
                <div class="card-body table-responsive">
                    <table class="table table-sm">
                        <thead class="table-light"><tr><th>When</th><th>Action</th><th>By</th><th>Note</th><th>IP</th></tr></thead>
                        <tbody>
                            @forelse ($finding->events as $event)
                                <tr>
                                    <td class="small">{{ $event->created_at }}</td>
                                    <td>{{ str_replace('_', ' ', $event->action) }}</td>
                                    <td>{{ $event->user?->name ?? 'scanner' }}</td>
                                    <td class="small text-break">{{ $event->note }}
                                        @if ($event->meta) <span class="text-muted">{{ json_encode($event->meta, JSON_UNESCAPED_SLASHES) }}</span> @endif</td>
                                    <td class="small">{{ $event->ip }}</td>
                                </tr>
                            @empty
                                <tr><td colspan="5" class="text-muted">No events.</td></tr>
                            @endforelse
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <div class="col-xl-4">
            @can('update', $finding)
                <div class="card">
                    <div class="card-header"><strong>Triage</strong></div>
                    <div class="card-body">
                        <form method="POST" action="{{ route(config('security.admin.route_name_prefix', 'admin.').'vulnerabilities.status', $finding) }}">
                            @csrf
                            <select name="status" class="form-select form-select-sm mb-2">
                                @foreach (['acknowledged' => 'Acknowledge (investigating)', 'resolved' => 'Resolved', 'false_positive' => 'False positive', 'open' => 'Re-open'] as $value => $label)
                                    <option value="{{ $value }}">{{ $label }}</option>
                                @endforeach
                            </select>
                            <textarea name="note" class="form-control form-control-sm mb-2" rows="2" placeholder="Note (required for false positive)" maxlength="2000"></textarea>
                            <button class="btn btn-sm btn-primary w-100">Update status</button>
                        </form>

                        @if ($finding->category === 'integrity' && $finding->sha256)
                            <hr>
                            <form method="POST" action="{{ route(config('security.admin.route_name_prefix', 'admin.').'vulnerabilities.accept-baseline', $finding) }}">
                                @csrf
                                <p class="small text-muted mb-1">If this change came from a verified deployment, accept the current content as the trusted baseline.</p>
                                <input type="text" name="note" class="form-control form-control-sm mb-2" placeholder="Deployment / commit reference" required minlength="5">
                                <button class="btn btn-sm btn-outline-success w-100">Accept as baseline</button>
                            </form>
                        @endif
                    </div>
                </div>
            @endcan

            @if (str_starts_with($finding->path, 'db://'))
                <div class="card mt-3">
                    <div class="card-header"><strong>Stored content</strong></div>
                    <div class="card-body small">
                        @if ($contentPreview !== null)
                            <div class="mb-1 text-muted">Sanitised version of the excerpt (escaped source shown):</div>
                            <pre class="bg-light border p-2" style="white-space: pre-wrap; max-height:160px; overflow:auto;">{{ $contentPreview }}</pre>
                        @endif
                        @can('admin_system_content-security-manage')
                            @if ($finding->category === 'stored_xss' && in_array($finding->status, \App\Models\Security\Finding::OPEN_STATUSES, true))
                                <form method="POST" action="{{ route(config('security.admin.route_name_prefix', 'admin.').'vulnerabilities.content.apply', $finding) }}">
                                    @csrf
                                    <div class="form-check mb-2">
                                        <input class="form-check-input" type="checkbox" name="confirm" value="1" id="confirm-apply" required>
                                        <label class="form-check-label" for="confirm-apply">I reviewed this record; replace it with the sanitised version (a backup of the original is kept).</label>
                                    </div>
                                    <button class="btn btn-sm btn-warning w-100">Apply sanitised version</button>
                                </form>
                            @elseif ($finding->category === 'suspicious_content')
                                <p class="mb-0">Plain-text field (escaped on output). It is never rewritten automatically — edit the record manually if needed.</p>
                            @endif
                            @foreach ($backups as $b)
                                <hr>
                                <div>Backup #{{ $b->id }} · applied {{ $b->applied_at }}{{ $b->restored_at ? ' · restored '.$b->restored_at : '' }}</div>
                                @if (! $b->restored_at)
                                    <form method="POST" action="{{ route(config('security.admin.route_name_prefix', 'admin.').'vulnerabilities.content.restore', $b) }}" class="mt-1">
                                        @csrf
                                        <textarea name="note" class="form-control form-control-sm mb-1" rows="2" placeholder="Why restore the unsanitised original? (min 10 chars)" required minlength="10"></textarea>
                                        <div class="form-check mb-1">
                                            <input class="form-check-input" type="checkbox" name="confirm" value="1" id="confirm-restore-{{ $b->id }}" required>
                                            <label class="form-check-label" for="confirm-restore-{{ $b->id }}">I understand this puts the flagged markup back.</label>
                                        </div>
                                        <button class="btn btn-sm btn-outline-danger w-100">Restore original</button>
                                    </form>
                                @endif
                            @endforeach
                        @endcan
                    </div>
                </div>
            @endif

            @can('quarantine', $finding)
                <div class="card mt-3 border-danger">
                    <div class="card-header text-danger"><strong>Quarantine</strong></div>
                    <div class="card-body">
                        <p class="small">Moves the file outside the web root (mode 0400) and records its metadata. Nothing is deleted.</p>
                        <form method="POST" action="{{ route(config('security.admin.route_name_prefix', 'admin.').'vulnerabilities.quarantine', $finding) }}"
                            onsubmit="return confirm('Move this file to quarantine? The original path will stop working.');">
                            @csrf
                            <input type="text" name="note" class="form-control form-control-sm mb-2" placeholder="Reason (optional)" maxlength="2000">
                            <button class="btn btn-sm btn-danger w-100">Quarantine file</button>
                        </form>
                    </div>
                </div>
            @endcan

            @if ($finding->quarantine)
                @php $q = $finding->quarantine; @endphp
                <div class="card mt-3">
                    <div class="card-header"><strong>Quarantine record</strong></div>
                    <div class="card-body small">
                        <div>Status: <strong>{{ $q->status }}</strong></div>
                        <div>Quarantined: {{ $q->quarantined_at }}</div>
                        <div>SHA-256: <code class="text-break">{{ $q->sha256 }}</code></div>
                        <div>Original perms: {{ $q->original_perms }} · size {{ number_format($q->size) }} B</div>
                        @if ($q->restored_at)<div>Restored: {{ $q->restored_at }}</div>@endif

                        @if ($q->status === 'quarantined')
                            @can('restore', $finding)
                                <hr>
                                <form method="POST" action="{{ route(config('security.admin.route_name_prefix', 'admin.').'vulnerabilities.restore', $q) }}">
                                    @csrf
                                    <p class="text-danger mb-1">Restoring puts the file back where it can be served. Only do this for confirmed false positives.</p>
                                    <textarea name="note" class="form-control form-control-sm mb-2" rows="2" placeholder="Justification (min 10 chars)" required minlength="10"></textarea>
                                    <input type="text" name="confirm_path" class="form-control form-control-sm mb-2" placeholder="Type the original path to confirm" required>
                                    <button class="btn btn-sm btn-outline-danger w-100">Restore file</button>
                                </form>
                            @endcan
                        @endif
                    </div>
                </div>
            @endif
        </div>
    </div>
@endsection
