<?php

namespace ThePrimeStudio\LaravelSentinel\Http\Controllers;

use Illuminate\Routing\Controller;


use ThePrimeStudio\LaravelSentinel\Models\SecurityAudit;
use Illuminate\Http\Request;

class SecurityAuditController extends Controller
{
    public function __construct()
    {
        
        $this->middleware('superadmin');
    }
    public function index()
    {
        $audits = SecurityAudit::latest()->paginate(15);
        return view('laravel-sentinel::security_audits.index', compact('audits'));
    }

    public function show($id)
    {
        $audit = SecurityAudit::findOrFail($id);

        $details = is_string($audit->result_json) ? json_decode($audit->result_json, true) : $audit->result_json;

        return view('laravel-sentinel::security_audits.show', compact('audit', 'details'));
    }
}
