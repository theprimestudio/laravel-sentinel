@extends('laravel-sentinel::layouts.app')
@section('page_title')
    Audit Details
@endsection
@section('content')
    <div class="card mt-3">
        <div class="card-header bg-white">
            <h4 class="card-title mb-0"><i class="cil-shield-alt text-primary"></i> Security Audit Details</h4>
        </div>
        <div class="card-body">
            <div class="row mb-4">
                <div class="col-md-3">
                    <p class="text-muted small mb-1">Date</p>
                    <div class="fw-bold">{{ $audit->created_at->format('M d, Y H:i:s') }}</div>
                </div>
                <div class="col-md-3">
                    <p class="text-muted small mb-1">Environment</p>
                    <div class="fw-bold">{{ ucfirst($audit->environment) }}</div>
                </div>
                <div class="col-md-3">
                    <p class="text-muted small mb-1">Score</p>
                    <div class="fw-bold">{{ $audit->score }}/100</div>
                </div>
                <div class="col-md-3">
                    <p class="text-muted small mb-1">Status</p>
                    <div>
                        @if ($audit->status === 'Passed')
                            <span class="badge bg-success">Passed</span>
                        @elseif($audit->status === 'Warning')
                            <span class="badge bg-warning text-dark">Warning</span>
                        @else
                            <span class="badge bg-danger">Failed</span>
                        @endif
                    </div>
                </div>
            </div>

            <hr>
            <h5 class="mt-4 mb-3">Security Checks</h5>

            <div class="table-responsive">
                <table class="table table-bordered table-hover align-middle">
                    <thead class="table-light">
                        <tr>
                            <th width="180">Severity</th>
                            <th>Message</th>
                        </tr>
                    </thead>
                    <tbody>

                        {{-- Critical --}}
                        @foreach ($details['critical'] ?? [] as $message)
                            <tr>
                                <td>
                                    <span class="badge bg-danger">
                                        <i class="cil-warning"></i>
                                        Critical
                                    </span>
                                </td>
                                <td>{{ $message }}</td>
                            </tr>
                        @endforeach

                        {{-- Warnings --}}
                        @foreach ($details['warnings'] ?? [] as $message)
                            <tr>
                                <td>
                                    <span class="badge bg-warning text-dark">
                                        <i class="cil-warning"></i>
                                        Warning
                                    </span>
                                </td>
                                <td>{{ $message }}</td>
                            </tr>
                        @endforeach

                        {{-- Passed --}}
                        @foreach ($details['passed'] ?? [] as $message)
                            <tr>
                                <td>
                                    <span class="badge bg-success">
                                        <i class="cil-check-circle"></i>
                                        Passed
                                    </span>
                                </td>
                                <td>{{ $message }}</td>
                            </tr>
                        @endforeach

                        @if (empty($details['critical']) && empty($details['warnings']) && empty($details['passed']))
                            <tr>
                                <td colspan="2" class="text-center text-muted py-4">
                                    No audit details available.
                                </td>
                            </tr>
                        @endif

                    </tbody>
                </table>
            </div>

            <div class="mt-4">
                <a href="{{ route(config('security.admin.route_name_prefix', 'admin.').'security-audits.index') }}" class="btn btn-secondary">Back to Audits</a>
            </div>
        </div>
    </div>
@endsection
