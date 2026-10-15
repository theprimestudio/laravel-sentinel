<?php

namespace ThePrimeStudio\LaravelSentinel\Services;

use ThePrimeStudio\LaravelSentinel\Models\Finding;
use ThePrimeStudio\LaravelSentinel\Models\FindingEvent;
use ThePrimeStudio\LaravelSentinel\Models\QuarantineItem;
// Host User decoupled
use Illuminate\Support\Facades\DB;
use RuntimeException;

/**
 * Moves suspicious files out of reach (outside the web root, mode 0400) while preserving
 * forensic metadata. Never deletes. Restoration is explicit, authorised and audited.
 */
use ThePrimeStudio\LaravelSentinel\Contracts\QuarantineInterface;

class QuarantineService implements QuarantineInterface
{
    public function root(): string
    {
        return rtrim(str_replace('\\', '/', (string) config('security.scanner.quarantine_path')), '/');
    }

    public function ensureRoot(): string
    {
        $root = $this->root();
        if (! is_dir($root) && ! @mkdir($root, 0700, true) && ! is_dir($root)) {
            throw new RuntimeException("Cannot create quarantine directory {$root}");
        }
        @chmod($root, 0700);

        // Defence in depth in case the directory is ever placed under a served path.
        $deny = $root.'/.htaccess';
        if (! file_exists($deny)) {
            @file_put_contents($deny, "Require all denied\nphp_flag engine off\n");
        }

        $publicRoot = realpath(public_path());
        $realRoot = realpath($root);
        if ($publicRoot && $realRoot && str_starts_with(str_replace('\\', '/', $realRoot).'/', str_replace('\\', '/', $publicRoot).'/')) {
            throw new RuntimeException('Quarantine directory must not be inside the public web root.');
        }

        return $root;
    }

    public function quarantine(Finding $finding, ?object $user = null, string $reason = 'manual', ?string $ip = null): QuarantineItem
    {
        $source = $this->absolute($finding->path);

        if (is_link($source)) {
            throw new RuntimeException('Refusing to quarantine a symbolic link target; remove the link manually after review.');
        }
        if (! is_file($source)) {
            throw new RuntimeException("File no longer exists at {$finding->path}");
        }

        $root = $this->ensureRoot();
        $sha = hash_file('sha256', $source);
        $stat = stat($source);
        $dir = $root.'/'.date('Y/m/d');
        if (! is_dir($dir)) {
            mkdir($dir, 0700, true);
        }
        $target = $dir.'/'.$finding->id.'_'.$sha.'.quarantine';

        $metadata = [
            'reason' => $reason,
            'finding_rule' => $finding->rule,
            'owner_uid' => $stat['uid'] ?? null,
            'group_gid' => $stat['gid'] ?? null,
            'inode' => $stat['ino'] ?? null,
            'ctime' => $stat['ctime'] ?? null,
            'atime' => $stat['atime'] ?? null,
            'host' => gethostname() ?: null,
        ];

        if (! @rename($source, $target)) {
            // Cross-device move: copy, verify, then unlink the original.
            if (! @copy($source, $target) || hash_file('sha256', $target) !== $sha) {
                @unlink($target);
                throw new RuntimeException('Failed to copy file into quarantine.');
            }
            if (! @unlink($source)) {
                @unlink($target);
                throw new RuntimeException('Copied to quarantine but could not remove original; quarantine rolled back.');
            }
        }

        @chmod($target, 0400);

        if (hash_file('sha256', $target) !== $sha) {
            throw new RuntimeException('Quarantined file hash mismatch.');
        }

        return DB::transaction(function () use ($finding, $user, $target, $sha, $stat, $metadata, $reason, $ip) {
            $item = QuarantineItem::create([
                'finding_id' => $finding->id,
                'original_path' => $finding->path,
                'quarantine_path' => $target,
                'sha256' => $sha,
                'size' => $stat['size'] ?? 0,
                'original_perms' => isset($stat['mode']) ? substr(sprintf('%o', $stat['mode']), -4) : null,
                'original_mtime' => $stat['mtime'] ?? null,
                'metadata' => $metadata,
                'status' => 'quarantined',
                'quarantined_by' => $user?->id,
                'quarantined_at' => now(),
            ]);

            $finding->update(['status' => 'quarantined']);

            FindingEvent::create([
                'finding_id' => $finding->id,
                'user_id' => $user?->id,
                'action' => $user ? 'quarantined' : 'auto_quarantined',
                'note' => $reason,
                'meta' => ['quarantine_id' => $item->id, 'sha256' => $sha],
                'ip' => $ip,
            ]);

            return $item;
        });
    }

    public function restore(QuarantineItem $item, User $user, ?string $note = null, ?string $ip = null): void
    {
        if ($item->status !== 'quarantined') {
            throw new RuntimeException('Item is not currently quarantined.');
        }

        $target = $this->absolute($item->original_path);
        if (file_exists($target)) {
            throw new RuntimeException('A file already exists at the original path; restore aborted.');
        }
        if (! is_file($item->quarantine_path) || hash_file('sha256', $item->quarantine_path) !== $item->sha256) {
            throw new RuntimeException('Quarantined copy is missing or its hash changed; restore aborted.');
        }

        $dir = dirname($target);
        if (! is_dir($dir)) {
            mkdir($dir, 0755, true);
        }

        @chmod($item->quarantine_path, 0600);
        if (! @rename($item->quarantine_path, $target)) {
            if (! @copy($item->quarantine_path, $target)) {
                @chmod($item->quarantine_path, 0400);
                throw new RuntimeException('Failed to restore file.');
            }
            @unlink($item->quarantine_path);
        }
        // Restore without execute bits regardless of original mode.
        @chmod($target, $item->original_perms ? (octdec($item->original_perms) & 0666) : 0644);
        if ($item->original_mtime) {
            @touch($target, (int) $item->original_mtime);
        }

        DB::transaction(function () use ($item, $user, $note, $ip) {
            $item->update(['status' => 'restored', 'restored_by' => $user->id, 'restored_at' => now()]);
            // Restored files go back to "acknowledged" so they stay visible, and scans won't re-quarantine
            // the same content automatically (fingerprint already exists).
            $item->finding?->update(['status' => 'acknowledged']);
            FindingEvent::create([
                'finding_id' => $item->finding_id,
                'user_id' => $user->id,
                'action' => 'restored',
                'note' => $note,
                'meta' => ['quarantine_id' => $item->id],
                'ip' => $ip,
            ]);
        });
    }

    protected function absolute(string $relative): string
    {
        $relative = str_replace('\\', '/', $relative);
        if (str_contains($relative, "\0") || preg_match('#(^|/)\.\.(/|$)#', $relative)) {
            throw new RuntimeException('Invalid path.');
        }

        return rtrim(str_replace('\\', '/', base_path()), '/').'/'.ltrim($relative, '/');
    }
}
