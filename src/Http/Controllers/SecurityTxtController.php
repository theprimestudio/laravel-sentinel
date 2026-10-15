<?php

namespace ThePrimeStudio\LaravelSentinel\Http\Controllers;

use Illuminate\Routing\Controller;

use ThePrimeStudio\LaravelSentinel\Models\SecurityTxt;
use Illuminate\Http\Response;

/** Public RFC 9116 endpoint: /.well-known/security.txt */
class SecurityTxtController extends Controller
{
    public function show(): Response
    {
        $record = SecurityTxt::query()->latest('id')->first();
        abort_unless($record, 404);

        return response($record->render(), 200, [
            'Content-Type' => 'text/plain; charset=utf-8',
            'Cache-Control' => 'public, max-age=3600',
            'X-Content-Type-Options' => 'nosniff',
        ]);
    }
}
