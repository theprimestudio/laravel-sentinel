<?php

namespace ThePrimeStudio\LaravelSentinel\Services;

use Symfony\Component\Process\Process;

/**
 * Thin, honest ClamAV adapter. Prefers the clamd daemon (fast, shared signature DB);
 * falls back to standalone clamscan for batch CLI scans. If neither works, it reports
 * itself unavailable — it never reports a file as clean when no engine ran.
 */
class ClamAvScanner
{
    /** @var callable(list<string>): array{0: int, 1: string, 2: string} */
    protected $runner;

    protected ?array $status = null;

    public function __construct(?callable $runner = null)
    {
        $this->runner = $runner ?? function (array $command): array {
            try {
                $process = new Process($command, null, null, null, (float) config('security.scanner.clamav.timeout', 120));
                $process->run();

                return [$process->getExitCode() ?? 2, $process->getOutput(), $process->getErrorOutput()];
            } catch (\Throwable $e) {
                return [127, '', $e->getMessage()];
            }
        };
    }

    /**
     * @return array{available: bool, engine: ?string, version: ?string, daemon: bool, reason: ?string}
     */
    public function status(): array
    {
        if ($this->status !== null) {
            return $this->status;
        }

        if (! config('security.scanner.clamav.enabled', true)) {
            return $this->status = ['available' => false, 'engine' => null, 'version' => null, 'daemon' => false, 'reason' => 'Disabled by configuration (SECURITY_CLAMAV_ENABLED=false).'];
        }

        $clamd = (string) config('security.scanner.clamav.clamdscan', 'clamdscan');
        [$code, $out] = ($this->runner)([$clamd, '--ping', '1']);
        if ($code === 0) {
            [, $ver] = ($this->runner)([$clamd, '--version']);

            return $this->status = ['available' => true, 'engine' => 'clamdscan', 'version' => trim($ver) ?: null, 'daemon' => true, 'reason' => null];
        }

        $clamscan = (string) config('security.scanner.clamav.clamscan', 'clamscan');
        [$code, $ver] = ($this->runner)([$clamscan, '--version']);
        if ($code === 0) {
            return $this->status = ['available' => true, 'engine' => 'clamscan', 'version' => trim($ver) ?: null, 'daemon' => false, 'reason' => 'clamd daemon not reachable; using slower standalone clamscan.'];
        }

        return $this->status = ['available' => false, 'engine' => null, 'version' => null, 'daemon' => false, 'reason' => 'ClamAV not installed or not executable (clamdscan/clamscan).'];
    }

    public function isAvailable(): bool
    {
        return $this->status()['available'];
    }

    public function hasDaemon(): bool
    {
        return $this->status()['daemon'];
    }

    /**
     * Scan files. Returns detections and whether the engine itself failed.
     *
     * @param  list<string>  $paths  absolute paths
     * @return array{infected: array<string, string>, error: ?string}
     */
    public function scan(array $paths): array
    {
        if ($paths === []) {
            return ['infected' => [], 'error' => null];
        }

        $status = $this->status();
        if (! $status['available']) {
            return ['infected' => [], 'error' => $status['reason']];
        }

        $bin = $status['engine'] === 'clamdscan'
            ? (string) config('security.scanner.clamav.clamdscan', 'clamdscan')
            : (string) config('security.scanner.clamav.clamscan', 'clamscan');

        $infected = [];
        $errors = [];
        foreach (array_chunk($paths, 100) as $chunk) {
            $command = array_merge([$bin, '--no-summary', '--infected'], $status['daemon'] ? ['--fdpass'] : [], $chunk);
            [$code, $out, $err] = ($this->runner)($command);

            foreach (preg_split('/\R/', $out) as $line) {
                if (preg_match('/^(.*):\s+(.+?)\s+FOUND$/', trim($line), $m)) {
                    $infected[$m[1]] = $m[2];
                }
            }

            // Exit codes: 0 clean, 1 virus found, 2+ error. Any error means the chunk is NOT verified clean.
            if ($code >= 2) {
                $errors[] = trim($err) !== '' ? trim($err) : "ClamAV exited with code {$code}";
            }
        }

        return ['infected' => $infected, 'error' => $errors === [] ? null : implode('; ', array_unique($errors))];
    }
}
