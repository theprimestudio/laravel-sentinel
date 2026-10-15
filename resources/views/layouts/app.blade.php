@php
    $hostLayout = config('security.admin.layout', 'admin.layouts.app');
@endphp
@if(view()->exists($hostLayout))
    @extends($hostLayout)
@else
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>@yield('page_title', 'Security') - {{ config('app.name', 'Laravel') }}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@coreui/icons/css/all.min.css">
    <style>
        body { background-color: #f4f6f9; font-family: system-ui, -apple-system, sans-serif; font-size: 0.95rem; }
        .card { border-radius: 8px; border: 1px solid #e2e8f0; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }
        .nav-link.active { font-weight: 600; }
        .badge { font-weight: 500; font-size: 0.8em; }
    </style>
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark bg-dark mb-4 shadow-sm">
    <div class="container-fluid">
        <a class="navbar-brand fw-bold" href="{{ route(config('security.admin.route_name_prefix', 'admin.').'security-dashboard.index') }}">
            🛡️ Security Center
        </a>
        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#secNav">
            <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="secNav">
            <ul class="navbar-nav me-auto mb-2 mb-lg-0">
                <li class="nav-item">
                    <a class="nav-link {{ request()->is('*security-dashboard*') ? 'active' : '' }}" href="{{ route(config('security.admin.route_name_prefix', 'admin.').'security-dashboard.index') }}">
                        <i class="cil-speedometer me-1"></i> Dashboard
                    </a>
                </li>
                <li class="nav-item">
                    <a class="nav-link {{ request()->is('*vulnerabilities*') ? 'active' : '' }}" href="{{ route(config('security.admin.route_name_prefix', 'admin.').'vulnerabilities.index') }}">
                        <i class="cil-bug me-1"></i> Vulnerabilities
                    </a>
                </li>
                <li class="nav-item">
                    <a class="nav-link {{ request()->is('*security-audits*') ? 'active' : '' }}" href="{{ route(config('security.admin.route_name_prefix', 'admin.').'security-audits.index') }}">
                        <i class="cil-shield-alt me-1"></i> Audits
                    </a>
                </li>
                <li class="nav-item">
                    <a class="nav-link {{ request()->is('*security-txt*') ? 'active' : '' }}" href="{{ route(config('security.admin.route_name_prefix', 'admin.').'security-txt.edit') }}">
                        <i class="cil-envelope-letter me-1"></i> security.txt
                    </a>
                </li>
            </ul>
        </div>
    </div>
</nav>

<div class="container-fluid px-4 pb-5">
    @if(session('messages'))
        @foreach(session('messages') as $m)
            <div class="alert alert-{{ $m['message_type'] ?? 'info' }} alert-dismissible fade show" role="alert">
                {{ $m['message'] }}
                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
            </div>
        @endforeach
    @endif
    @if(session('status'))
        <div class="alert alert-success alert-dismissible fade show" role="alert">
            {{ session('status') }}
            <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
        </div>
    @endif

    @yield('content')
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
@endif