@extends('laravel-sentinel::layouts.app')
@section('page_title')
    security.txt
@endsection
@section('content')
    @if ($errors->any())
        <div class="alert alert-danger mt-3">@foreach ($errors->all() as $error)<div>{{ $error }}</div>@endforeach</div>
    @endif

    <div class="row g-3 mt-1">
        <div class="col-xl-7">
            <div class="card">
                <div class="card-header"><strong>security.txt (RFC 9116)</strong> — served at
                    <a href="{{ url('/.well-known/security.txt') }}" target="_blank" rel="noopener">/.well-known/security.txt</a></div>
                <div class="card-body">
                    @if ($record && $record->expires_at->isPast())
                        <div class="alert alert-danger">This file EXPIRED on {{ $record->expires_at }}. Researchers will treat it as stale — set a new expiry.</div>
                    @elseif ($record && $record->expires_at->lt(now()->addDays(30)))
                        <div class="alert alert-warning">Expires {{ $record->expires_at->diffForHumans() }}.</div>
                    @endif
                    <form method="POST" action="{{ route(config('security.admin.route_name_prefix', 'admin.').'security-txt.update') }}">
                        @csrf
                        @method('PUT')
                        <div class="mb-3">
                            <label class="form-label fw-semibold">Contact <span class="text-danger">*</span></label>
                            <textarea name="contacts" rows="3" class="form-control" required placeholder="mailto:security@example.edu.pk&#10;https://example.edu.pk/report">{{ old('contacts', $record?->contacts) }}</textarea>
                            <div class="form-text">One per line: <code>mailto:</code>, <code>https://</code> or <code>tel:</code>. Listed in order of preference.</div>
                        </div>
                        <div class="mb-3">
                            <label class="form-label fw-semibold">Expires <span class="text-danger">*</span></label>
                            <input type="datetime-local" name="expires_at" class="form-control" required
                                value="{{ old('expires_at', ($record?->expires_at ?? now()->addMonths(11))->format('Y-m-d\TH:i')) }}">
                            <div class="form-text">Must be in the future and no more than one year ahead.</div>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Encryption</label>
                            <textarea name="encryption" rows="2" class="form-control" placeholder="https://example.edu.pk/pgp-key.txt">{{ old('encryption', $record?->encryption) }}</textarea>
                            <div class="form-text"><code>https://</code>, <code>dns:</code> or <code>openpgp4fpr:</code>. Never paste a private key.</div>
                        </div>
                        <div class="row">
                            <div class="col-md-6 mb-3">
                                <label class="form-label">Policy</label>
                                <textarea name="policy" rows="2" class="form-control" placeholder="https://…/disclosure-policy">{{ old('policy', $record?->policy) }}</textarea>
                            </div>
                            <div class="col-md-6 mb-3">
                                <label class="form-label">Acknowledgments</label>
                                <textarea name="acknowledgments" rows="2" class="form-control" placeholder="https://…/hall-of-fame">{{ old('acknowledgments', $record?->acknowledgments) }}</textarea>
                            </div>
                            <div class="col-md-6 mb-3">
                                <label class="form-label">Hiring</label>
                                <textarea name="hiring" rows="2" class="form-control">{{ old('hiring', $record?->hiring) }}</textarea>
                            </div>
                            <div class="col-md-6 mb-3">
                                <label class="form-label">Canonical</label>
                                <textarea name="canonical" rows="2" class="form-control" placeholder="{{ $defaultCanonical }}">{{ old('canonical', $record?->canonical) }}</textarea>
                                <div class="form-text">Defaults to {{ $defaultCanonical }}</div>
                            </div>
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Preferred-Languages</label>
                            <input type="text" name="preferred_languages" class="form-control" placeholder="en, ur" value="{{ old('preferred_languages', $record?->preferred_languages) }}">
                        </div>
                        <button class="btn btn-primary">Save</button>
                    </form>
                </div>
            </div>
        </div>
        <div class="col-xl-5">
            <div class="card">
                <div class="card-header"><strong>Current published file</strong></div>
                <div class="card-body">
                    @if ($preview)
                        <pre class="bg-light border p-2 small mb-0" style="white-space: pre-wrap;">{{ $preview }}</pre>
                    @else
                        <p class="text-muted mb-0">Not configured — /.well-known/security.txt returns 404.</p>
                    @endif
                    @if ($record)
                        <div class="small text-muted mt-2">Last changed {{ $record->updated_at }} (changes are recorded in the activity log and security events).</div>
                    @endif
                </div>
            </div>
        </div>
    </div>
@endsection
