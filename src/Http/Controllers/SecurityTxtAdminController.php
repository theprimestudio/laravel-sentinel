<?php

namespace ThePrimeStudio\LaravelSentinel\Http\Controllers;

use Illuminate\Routing\Controller;


use ThePrimeStudio\LaravelSentinel\Models\SecurityTxt;
use ThePrimeStudio\LaravelSentinel\Services\SecurityEventRecorder;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Session;
use Illuminate\View\View;

class SecurityTxtAdminController extends Controller
{
    protected const URI_LINE = '/^https:\/\/[^\s<>"]+$/';

    public function __construct()
    {
        
        if (config('security.admin.permissions_enabled', true)) { $this->middleware('permission:admin_system_security-txt-manage'); }
    }

    public function edit(): View
    {
        $record = SecurityTxt::query()->latest('id')->first();

        return view('laravel-sentinel::security_txt.edit', [
            'record' => $record,
            'defaultCanonical' => rtrim((string) config('app.url'), '/').'/.well-known/security.txt',
            'preview' => $record?->render(),
        ]);
    }

    public function update(Request $request, SecurityEventRecorder $recorder): RedirectResponse
    {
        $lines = fn (string $pattern, int $max = 10) => function (string $attribute, mixed $value, \Closure $fail) use ($pattern, $max) {
            $items = SecurityTxt::splitLines((string) $value);
            if (count($items) > $max) {
                $fail("At most {$max} entries are allowed.");
            }
            foreach ($items as $item) {
                if (strlen($item) > 500 || ! preg_match($pattern, $item)) {
                    $fail("Invalid entry: \"".mb_substr($item, 0, 80).'"');
                }
            }
        };

        $data = $request->validate([
            'contacts' => ['required', 'string', 'max:5000', $lines('/^(mailto:[^\s@<>"]+@[^\s@<>"]+\.[^\s@<>"]+|https:\/\/[^\s<>"]+|tel:\+?[0-9][0-9 ()\-]{4,30})$/')],
            'expires_at' => ['required', 'date', 'after:now', 'before_or_equal:'.now()->addYear()->toDateTimeString()],
            'encryption' => ['nullable', 'string', 'max:2000', $lines('/^(https:\/\/[^\s<>"]+|dns:[^\s<>"]+|openpgp4fpr:[0-9a-fA-F]{40})$/', 5)],
            'acknowledgments' => ['nullable', 'string', 'max:2000', $lines(self::URI_LINE, 5)],
            'policy' => ['nullable', 'string', 'max:2000', $lines(self::URI_LINE, 5)],
            'hiring' => ['nullable', 'string', 'max:2000', $lines(self::URI_LINE, 5)],
            'canonical' => ['nullable', 'string', 'max:2000', $lines(self::URI_LINE, 5)],
            'preferred_languages' => ['nullable', 'string', 'max:100', 'regex:/^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*(\s*,\s*[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*)*$/'],
        ], [
            'expires_at.before_or_equal' => 'RFC 9116 recommends an expiry less than a year ahead.',
        ]);

        foreach (['contacts', 'encryption', 'acknowledgments', 'policy', 'hiring', 'canonical'] as $f) {
            $data[$f] = implode("\n", SecurityTxt::splitLines($data[$f] ?? '')) ?: null;
        }
        $data['canonical'] ??= rtrim((string) config('app.url'), '/').'/.well-known/security.txt';
        $data['updated_by'] = $request->user()->id;

        DB::transaction(function () use ($data, $request, $recorder) {
            $record = SecurityTxt::query()->latest('id')->lockForUpdate()->first() ?? new SecurityTxt;
            $old = $record->exists ? $record->only(array_keys($data)) : [];
            $record->fill($data)->save();

            activity('SecurityTxt')
                ->causedBy($request->user())
                ->performedOn($record)
                ->event($old ? 'updated' : 'created')
                ->withProperties(['old' => $old, 'attributes' => $record->only(array_keys($data))])
                ->log('security.txt '.($old ? 'updated' : 'created'));
            $recorder->record('security_txt_change', 'low', 'security.txt was '.($old ? 'updated' : 'created'), ['changed' => array_keys(array_diff_assoc(array_map('strval', $record->only(array_keys($data))), array_map('strval', $old)))]);
        });

        Session::flash('messages', [['message' => 'security.txt saved.', 'message_type' => 'success']]);

        return redirect()->route('admin.security-txt.edit');
    }
}
