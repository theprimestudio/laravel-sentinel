<?php

namespace ThePrimeStudio\LaravelSentinel\Services;

use ThePrimeStudio\LaravelSentinel\Models\SecurityAlert;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Schema;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Str;
use Illuminate\Validation\ValidationException;

class FileSecurityService
{
    /**
     * Dangerous extensions that must never be uploaded or served.
     *
     * @var list<string>
     */
    protected array $blockedExtensions = [
        'php', 'php3', 'php4', 'php5', 'php56', 'php7', 'php71', 'php8', 'phtml', 'pht', 'phps', 'phar',
        'shtml', 'shtm', 'stm', 'html', 'htm', 'xhtml', 'svg', 'svgz', 'xml', 'inc', 'cgi', 'pl', 'py', 'sh', 'bash', 'exe', 'bat', 'cmd',
        'vbs', 'js', 'jar', 'htaccess', 'htpasswd', 'env', 'ini', 'conf',
        'sql', 'bak', 'swp', 'config',
    ];

    /**
     * Dangerous content patterns that indicate embedded webshells or script injection.
     *
     * @var list<string>
     */
    protected array $dangerousContentSignatures = [
        '<?php',
        '<?=',
        '<script',
        'eval(',
        'eval (',
        'base64_decode(',
        'base64_decode (',
        'system(',
        'system (',
        'shell_exec(',
        'shell_exec (',
        'passthru(',
        'passthru (',
        'proc_open(',
        'proc_open (',
        'popen(',
        'popen (',
        'assert(',
        'assert (',
    ];

    /**
     * Allowed image MIME types and their canonical extensions.
     *
     * @var array<string, string>
     */
    protected array $allowedImageMimes = [
        'image/jpeg' => 'jpg',
        'image/png'  => 'png',
        'image/webp' => 'webp',
        'image/gif'  => 'gif',
    ];

    /**
     * Allowed MIME types for generic uploads (settings, media) and the extension
     * they are stored with. Extensions are never taken from client input.
     *
     * @var array<string, string>
     */
    protected array $allowedUploadMimes = [
        'image/jpeg' => 'jpg',
        'image/png' => 'png',
        'image/webp' => 'webp',
        'image/gif' => 'gif',
        'image/heic' => 'heic',
        'image/heif' => 'heic',
        'image/x-icon' => 'ico',
        'image/vnd.microsoft.icon' => 'ico',
        'application/pdf' => 'pdf',
        'text/plain' => 'txt',
        'text/csv' => 'csv',
        'application/msword' => 'doc',
        'application/vnd.ms-excel' => 'xls',
        'application/vnd.ms-powerpoint' => 'ppt',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document' => 'docx',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' => 'xlsx',
        'application/vnd.openxmlformats-officedocument.presentationml.presentation' => 'pptx',
    ];

    /**
     * Resolve the storage extension for a detected MIME type, or null when not allowed.
     */
    public function safeExtensionForMime(?string $mimeType): ?string
    {
        return $this->allowedUploadMimes[strtolower((string) $mimeType)] ?? null;
    }

    /**
     * Scan an uploaded file for security threats.
     *
     * @param  UploadedFile  $file
     * @param  list<string>  $allowedExtensions
     * @return array{safe: bool, reason: string|null}
     */
    public function scanUploadedFile(UploadedFile $file, array $allowedExtensions = []): array
    {
        $originalName = $file->getClientOriginalName();
        $clientExt = strtolower($file->getClientOriginalExtension());
        $realMime = $file->getMimeType();

        // Check for null bytes or path traversal in filename
        if (str_contains($originalName, "\0") || str_contains($originalName, '..')) {
            $this->logSecurityThreat('Path traversal / null byte attempt in filename', $originalName);

            return ['safe' => false, 'reason' => 'Filename contains invalid characters.'];
        }

        // Check against blocked extensions list
        if (in_array($clientExt, $this->blockedExtensions, true)) {
            $this->logSecurityThreat('Blocked extension upload attempt', "Extension: {$clientExt}, File: {$originalName}");

            return ['safe' => false, 'reason' => "Files with .{$clientExt} extension are not allowed."];
        }

        // Check for double extension patterns (e.g. image.php.jpg)
        if ($this->hasDangerousDoubleExtension($originalName)) {
            $this->logSecurityThreat('Double extension bypass attempt', "File: {$originalName}");

            return ['safe' => false, 'reason' => 'Files with compound or deceptive extensions are forbidden.'];
        }

        // Check if allowed extensions were specified
        if (! empty($allowedExtensions) && ! in_array($clientExt, array_map('strtolower', $allowedExtensions), true)) {
            return ['safe' => false, 'reason' => "Extension .{$clientExt} is not permitted for this field."];
        }

        // Inspect file content
        $content = @file_get_contents($file->getRealPath());
        if ($content === false) {
            return ['safe' => false, 'reason' => 'Unable to read uploaded file contents.'];
        }

        $contentScan = $this->scanContentForMalware($content, $realMime);
        if (! $contentScan['safe']) {
            $this->logSecurityThreat('Malicious payload detected in uploaded file', "File: {$originalName}, Threat: {$contentScan['reason']}");

            return $contentScan;
        }

        // Same heuristics the background scanner uses (web shells, SSI, handler overrides, polyglots).
        $heuristic = app(\App\Services\Security\HeuristicAnalyzer::class)
            ->analyze($originalName, $content, ['in_upload_root' => true]);
        if ($heuristic['confidence'] >= 65) {
            $this->logSecurityThreat('Upload rejected by heuristic scanner', "File: {$originalName}, Rule: {$heuristic['rule']} ({$heuristic['confidence']}%)");

            return ['safe' => false, 'reason' => 'The file was rejected by the security scanner.'];
        }

        return $this->scanWithClamAv($file->getRealPath(), $originalName);
    }

    /**
     * Signature scan of an upload before it is stored. Only the clamd daemon is used at
     * request time (standalone clamscan takes seconds to load signatures). When ClamAV is
     * required by policy and unavailable or erroring, the upload is rejected (fail closed).
     *
     * @return array{safe: bool, reason: string|null}
     */
    public function scanWithClamAv(string $absolutePath, string $originalName): array
    {
        $clamav = app(\App\Services\Security\ClamAvScanner::class);
        $required = (bool) config('security.uploads.clamav_required', false);

        if (! $clamav->hasDaemon()) {
            if ($required) {
                $this->logSecurityThreat('Upload rejected: malware scanner unavailable', "File: {$originalName}");

                return ['safe' => false, 'reason' => 'Uploads are temporarily unavailable because the malware scanner is offline.'];
            }

            return ['safe' => true, 'reason' => null];
        }

        $result = $clamav->scan([$absolutePath]);
        if ($result['infected'] !== []) {
            $this->logSecurityThreat('Upload rejected: ClamAV detection', "File: {$originalName}, Signature: ".implode(', ', $result['infected']));

            return ['safe' => false, 'reason' => 'The file was rejected by the malware scanner.'];
        }
        if ($result['error'] !== null && $required) {
            $this->logSecurityThreat('Upload rejected: ClamAV error', "File: {$originalName}, Error: {$result['error']}");

            return ['safe' => false, 'reason' => 'The file could not be verified by the malware scanner.'];
        }

        return ['safe' => true, 'reason' => null];
    }

    /**
     * Inspect file content for malicious code, embedded PHP, or dangerous script signatures.
     *
     * @param  string  $content
     * @param  string|null  $mimeType
     * @return array{safe: bool, reason: string|null}
     */
    public function scanContentForMalware(string $content, ?string $mimeType = null): array
    {
        $lowerContent = strtolower($content);

        // Check for PHP tags and common webshell execution primitives
        foreach ($this->dangerousContentSignatures as $signature) {
            if (str_contains($lowerContent, $signature)) {
                return [
                    'safe' => false,
                    'reason' => "Dangerous signature [{$signature}] detected in file content.",
                ];
            }
        }

        // PDF specific validation: check for embedded JavaScript or Launch actions
        if ($mimeType === 'application/pdf' || str_starts_with($content, '%PDF-')) {
            if (
                str_contains($content, '/JavaScript') ||
                str_contains($content, '/JS') ||
                str_contains($content, '/Launch') ||
                str_contains($content, '/EmbeddedFiles')
            ) {
                return [
                    'safe' => false,
                    'reason' => 'PDF contains active executable scripts or Launch actions.',
                ];
            }
        }

        // SVG specific validation: block scripts and event handlers
        if ($mimeType === 'image/svg+xml' || str_contains($lowerContent, '<svg')) {
            if (
                str_contains($lowerContent, '<script') ||
                str_contains($lowerContent, 'javascript:') ||
                preg_match('/\bon[a-z]+\s*=/i', $lowerContent)
            ) {
                return [
                    'safe' => false,
                    'reason' => 'SVG contains active script tags or embedded event handlers.',
                ];
            }
        }

        return ['safe' => true, 'reason' => null];
    }

    /**
     * Validate, sanitize, and safely store a base64 encoded image.
     *
     * @param  string  $base64Data
     * @param  string  $disk
     * @param  string  $folderPath
     * @return string Relative saved path
     *
     * @throws ValidationException
     */
    public function sanitizeAndStoreBase64Image(string $base64Data, string $disk = 'private', string $folderPath = 'user/profile/'): string
    {
        // Extract raw base64 data if it has the data:image prefix
        if (str_contains($base64Data, ';base64,')) {
            [, $rawData] = explode(';base64,', $base64Data, 2);
        } else {
            $rawData = $base64Data;
        }

        $decoded = base64_decode($rawData, true);
        if ($decoded === false || strlen($decoded) === 0) {
            throw ValidationException::withMessages([
                'image' => 'The provided image data is corrupt or not valid base64.',
            ]);
        }

        // Verify true MIME type via finfo
        $finfo = new \finfo(FILEINFO_MIME_TYPE);
        $detectedMime = $finfo->buffer($decoded);

        if (! array_key_exists($detectedMime, $this->allowedImageMimes)) {
            $this->logSecurityThreat('Rejected invalid base64 image MIME', "Detected MIME: {$detectedMime}");
            throw ValidationException::withMessages([
                'image' => 'The uploaded file is not a valid image. Only JPEG, PNG, WebP, and GIF are allowed.',
            ]);
        }

        // Scan the binary image content for embedded PHP/webshell signatures
        $scan = $this->scanContentForMalware($decoded, $detectedMime);
        if (! $scan['safe']) {
            $this->logSecurityThreat('Malicious base64 image rejected', $scan['reason']);
            throw ValidationException::withMessages([
                'image' => 'Security check failed: Suspicious content was detected in the uploaded image.',
            ]);
        }

        // Verify image decodeability
        $imageInfo = @getimagesizefromstring($decoded);
        if ($imageInfo === false) {
            throw ValidationException::withMessages([
                'image' => 'The file claims to be an image but could not be parsed by the image processor.',
            ]);
        }

        $extension = $this->allowedImageMimes[$detectedMime];
        $datePrefix = date('Y/m/d/');
        $filename = $datePrefix . Str::random(40) . '.' . $extension;
        $fullRelativePath = rtrim($folderPath, '/') . '/' . $filename;

        $tmp = tempnam(sys_get_temp_dir(), 'b64img');
        file_put_contents($tmp, $decoded);
        try {
            $av = $this->scanWithClamAv($tmp, 'base64-image');
        } finally {
            @unlink($tmp);
        }
        if (! $av['safe']) {
            throw ValidationException::withMessages(['image' => $av['reason']]);
        }

        Storage::disk($disk)->put($fullRelativePath, $decoded);

        return $fullRelativePath;
    }

    /**
     * Validate, sanitize, and safely store an uploaded image file.
     *
     * @param  UploadedFile  $file
     * @param  string  $disk
     * @param  string  $folderPath
     * @return string Relative saved path
     *
     * @throws ValidationException
     */
    public function sanitizeAndStoreUploadedImage(UploadedFile $file, string $disk = 'private', string $folderPath = 'user/profile/'): string
    {
        $scan = $this->scanUploadedFile($file, ['jpg', 'jpeg', 'png', 'webp', 'gif']);
        if (! $scan['safe']) {
            throw ValidationException::withMessages([
                'image' => $scan['reason'] ?? 'Security scan failed for uploaded image.',
            ]);
        }

        $imageInfo = @getimagesize($file->getRealPath());
        if ($imageInfo === false) {
            $this->logSecurityThreat('Fake image upload attempt', 'getimagesize failed on '.$file->getClientOriginalName());
            throw ValidationException::withMessages([
                'image' => 'The file claims to be an image but could not be parsed by the image processor.',
            ]);
        }

        $finfo = new \finfo(FILEINFO_MIME_TYPE);
        $detectedMime = $finfo->file($file->getRealPath());

        if (! array_key_exists($detectedMime, $this->allowedImageMimes)) {
            $this->logSecurityThreat('Rejected invalid image MIME', "Detected MIME: {$detectedMime}");
            throw ValidationException::withMessages([
                'image' => 'The uploaded file is not a valid image. Only JPEG, PNG, WebP, and GIF are allowed.',
            ]);
        }

        $extension = $this->allowedImageMimes[$detectedMime];
        $datePrefix = date('Y/m/d/');
        $filename = $datePrefix . Str::random(40) . '.' . $extension;
        $fullRelativePath = rtrim($folderPath, '/') . '/' . $filename;

        Storage::disk($disk)->putFileAs(rtrim($folderPath, '/') . '/' . $datePrefix, $file, basename($filename));

        return $fullRelativePath;
    }

    /**
     * Get list of blocked dangerous extensions.
     *
     * @return list<string>
     */
    public function getBlockedExtensions(): array
    {
        return $this->blockedExtensions;
    }

    /**
     * Check if extension is dangerous.
     */
    public function isDangerousExtension(string $extension): bool
    {
        return in_array(strtolower(ltrim($extension, '.')), $this->blockedExtensions, true);
    }

    /**
     * Check if a filename contains dangerous double extension (e.g. evil.php.jpg).
     */
    public function hasDangerousDoubleExtension(string $filename): bool
    {
        $parts = explode('.', strtolower($filename));
        if (count($parts) < 3) {
            return false;
        }

        // Exclude the last extension and check all previous parts
        array_pop($parts);
        foreach ($parts as $part) {
            if (in_array($part, $this->blockedExtensions, true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Audit an existing file on a given disk.
     *
     * @param  string  $disk
     * @param  string  $path
     * @return array{is_vulnerable: bool, is_hidden: bool, threat: string|null}
     */
    public function auditStorageFile(string $disk, string $path): array
    {
        $basename = basename($path);
        $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));

        // Hidden files
        if (str_starts_with($basename, '.')) {
            return [
                'is_vulnerable' => true,
                'is_hidden' => true,
                'threat' => 'Hidden or system dotfile',
            ];
        }

        // Sensitive extensions
        if (in_array($ext, $this->blockedExtensions, true)) {
            return [
                'is_vulnerable' => true,
                'is_hidden' => false,
                'threat' => "Executable or sensitive extension (.{$ext})",
            ];
        }

        // Double extensions
        if ($this->hasDangerousDoubleExtension($basename)) {
            return [
                'is_vulnerable' => true,
                'is_hidden' => false,
                'threat' => 'Deceptive double extension detected',
            ];
        }

        // Deep content check if file exists and is readable
        if (Storage::disk($disk)->exists($path)) {
            $size = Storage::disk($disk)->size($path);
            // Only inspect content for files under 10MB to avoid memory exhaustion
            if ($size < 10 * 1024 * 1024) {
                $content = Storage::disk($disk)->get($path);
                $mime = Storage::disk($disk)->mimeType($path);
                $scan = $this->scanContentForMalware($content, $mime);
                if (! $scan['safe']) {
                    return [
                        'is_vulnerable' => true,
                        'is_hidden' => false,
                        'threat' => $scan['reason'],
                    ];
                }
            }
        }

        return [
            'is_vulnerable' => false,
            'is_hidden' => false,
            'threat' => null,
        ];
    }

    /**
     * Log a security alert in the database and Laravel log.
     */
    public function logSecurityThreat(string $title, ?string $details = null): void
    {
        Log::warning("[Security Threat] {$title} - {$details}");

        if (Schema::hasTable('security_alerts')) {
            try {
                SecurityAlert::create([
                    'severity' => 'critical',
                    'title' => $title,
                    'description' => sprintf(
                        "%s\nIP: %s\nUser: %s\nURL: %s",
                        $details ?? 'No additional details',
                        request()->ip(),
                        auth()->id() ?? 'Guest',
                        request()->fullUrl()
                    ),
                ]);
            } catch (\Throwable $e) {
                // Silently ignore DB write errors to avoid crashing requests
            }
        }

        // Feed the security dashboard / incidents (recorder never throws).
        $isUpload = stripos($title, 'upload') !== false || stripos($title, 'image') !== false || stripos($title, 'extension') !== false;
        app(\App\Services\Security\SecurityEventRecorder::class)->record(
            $isUpload ? 'malicious_upload' : 'blocked_request',
            'high',
            $title,
            ['details' => $details],
            $isUpload ? 'rejected' : 'blocked'
        );
    }
}
