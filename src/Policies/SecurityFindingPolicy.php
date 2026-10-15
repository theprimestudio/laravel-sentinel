<?php

namespace ThePrimeStudio\LaravelSentinel\Policies;

use ThePrimeStudio\LaravelSentinel\Models\Finding;

class SecurityFindingPolicy
{
    public function viewAny(object $user): bool
    {
        return $this->checkPermission($user, 'admin_system_vulnerability-list');
    }

    public function view(object $user, Finding $finding): bool
    {
        return $this->checkPermission($user, 'admin_system_vulnerability-show');
    }

    public function update(object $user, Finding $finding): bool
    {
        return $this->checkPermission($user, 'admin_system_vulnerability-manage');
    }

    public function quarantine(object $user, Finding $finding): bool
    {
        return $this->checkPermission($user, 'admin_system_vulnerability-quarantine')
            && in_array($finding->status, Finding::OPEN_STATUSES, true)
            && ! str_starts_with($finding->path, 'db://');
    }

    public function restore(object $user, Finding $finding): bool
    {
        return $this->checkPermission($user, 'admin_system_vulnerability-restore');
    }

    protected function checkPermission(object $user, string $permission): bool
    {
        // 1. Superadmin bypass if configured
        if (config('security.admin.superadmin_bypass', true) && (isset($user->is_superadmin) && $user->is_superadmin)) {
            return true;
        }

        // 2. Spatie Permission integration if available
        if (config('security.admin.permissions_enabled', true) && method_exists($user, 'can')) {
            try {
                if ($user->can($permission)) {
                    return true;
                }
            } catch (\Throwable $e) {
                // fall through
            }
        }

        // 3. Default to true in non-permission environments if authenticated
        return ! config('security.admin.permissions_enabled', false);
    }
}