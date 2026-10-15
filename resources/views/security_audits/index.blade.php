@extends('laravel-sentinel::layouts.app')
@section('page_title')
    Security Audits
@endsection
@section('content')
    <div class="card mt-3">
        <div class="card-body">
            <div class="d-flex justify-content-between mb-3">
                <h4 class="card-title mb-0">Security Audits</h4>
            </div>
            <div class="table-responsive">
                <table class="table table-bordered table-striped">
                    <thead class="table-light">
                        <tr>
                            <th>Date</th>
                            <th>Environment</th>
                            <th>Score</th>
                            <th>Status</th>
                            <th>Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        @forelse($audits as $audit)
                            <tr>
                                <td>{{ $audit->created_at->format('M d, Y H:i:s') }}</td>
                                <td>{{ ucfirst($audit->environment) }}</td>
                                <td>{{ $audit->score }}/100</td>
                                <td>
                                    @if($audit->status === 'Passed')
                                        <span class="badge bg-success">Passed</span>
                                    @elseif($audit->status === 'Warning')
                                        <span class="badge bg-warning text-dark">Warning</span>
                                    @else
                                        <span class="badge bg-danger">Failed</span>
                                    @endif
                                </td>
                                <td>
                                    <a href="{{ route(config('security.admin.route_name_prefix', 'admin.').'security-audits.show', $audit->id) }}" class="btn btn-sm btn-primary">View Details</a>
                                </td>
                            </tr>
                        @empty
                            <tr>
                                <td colspan="5" class="text-center">No audits found.</td>
                            </tr>
                        @endforelse
                    </tbody>
                </table>
            </div>
            
            <div class="mt-3">
                {{ $audits->links() }}
            </div>
        </div>
    </div>
@endsection
