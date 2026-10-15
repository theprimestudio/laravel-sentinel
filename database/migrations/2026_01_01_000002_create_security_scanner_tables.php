<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        $usersTable = config('security.auth.table', 'users');
        $hasUsers = Schema::hasTable($usersTable);

        if (! Schema::hasTable('security_scan_runs')) {
            Schema::create('security_scan_runs', function (Blueprint $table) {
                $table->id();
                $table->string('mode', 20);
                $table->string('status', 20)->index();
                $table->boolean('dry_run')->default(false);
                $table->timestamp('started_at')->nullable();
                $table->timestamp('finished_at')->nullable();
                $table->unsignedInteger('files_seen')->default(0);
                $table->unsignedInteger('files_scanned')->default(0);
                $table->unsignedInteger('files_changed')->default(0);
                $table->unsignedInteger('files_deleted')->default(0);
                $table->unsignedInteger('findings_count')->default(0);
                $table->unsignedInteger('errors_count')->default(0);
                $table->json('engines')->nullable();
                $table->json('coverage_gaps')->nullable();
                $table->json('roots')->nullable();
                $table->text('checkpoint')->nullable();
                $table->unsignedBigInteger('resumed_from_id')->nullable();
                $table->text('error')->nullable();
                $table->string('host')->nullable();
                $table->unsignedInteger('pid')->nullable();
                $table->timestamps();
            });
        }

        if (! Schema::hasTable('security_file_inventory')) {
            Schema::create('security_file_inventory', function (Blueprint $table) {
                $table->id();
                $table->char('path_hash', 64)->unique();
                $table->text('path');
                $table->char('sha256', 64)->nullable();
                $table->char('baseline_sha256', 64)->nullable();
                $table->unsignedBigInteger('size')->default(0);
                $table->unsignedBigInteger('mtime')->default(0);
                $table->string('perms', 8)->nullable();
                $table->boolean('is_critical')->default(false);
                $table->timestamp('first_seen_at')->nullable();
                $table->timestamp('last_seen_at')->nullable();
                $table->timestamp('last_scanned_at')->nullable();
                $table->timestamp('missing_since')->nullable()->index();
                $table->timestamps();
            });
        }

        if (! Schema::hasTable('security_findings')) {
            Schema::create('security_findings', function (Blueprint $table) use ($usersTable, $hasUsers) {
                $table->id();
                $table->char('fingerprint', 64)->unique();
                $table->text('path');
                $table->char('sha256', 64)->nullable();
                $table->string('category', 40)->index();
                $table->string('rule', 80);
                $table->string('severity', 10)->index();
                $table->unsignedTinyInteger('confidence')->default(0);
                $table->json('reasons')->nullable();
                $table->text('evidence')->nullable();
                $table->text('remediation')->nullable();
                $table->string('status', 20)->default('open')->index();
                $table->unsignedInteger('occurrences')->default(1);
                $table->timestamp('first_detected_at')->nullable();
                $table->timestamp('last_detected_at')->nullable();
                $table->foreignId('scan_run_id')->nullable()->constrained('security_scan_runs')->nullOnDelete();
                
                $col = $table->foreignId('resolved_by')->nullable();
                if ($hasUsers) {
                    $col->constrained($usersTable)->nullOnDelete();
                }

                $table->timestamp('resolved_at')->nullable();
                $table->timestamps();
            });
        }

        if (! Schema::hasTable('security_quarantine')) {
            Schema::create('security_quarantine', function (Blueprint $table) use ($usersTable, $hasUsers) {
                $table->id();
                $table->foreignId('finding_id')->nullable()->constrained('security_findings')->nullOnDelete();
                $table->text('original_path');
                $table->text('quarantine_path');
                $table->char('sha256', 64);
                $table->unsignedBigInteger('size')->default(0);
                $table->string('original_perms', 8)->nullable();
                $table->unsignedBigInteger('original_mtime')->nullable();
                $table->json('metadata')->nullable();
                $table->string('status', 20)->default('quarantined')->index();
                
                $qCol = $table->foreignId('quarantined_by')->nullable();
                if ($hasUsers) {
                    $qCol->constrained($usersTable)->nullOnDelete();
                }
                $table->timestamp('quarantined_at')->nullable();

                $rCol = $table->foreignId('restored_by')->nullable();
                if ($hasUsers) {
                    $rCol->constrained($usersTable)->nullOnDelete();
                }
                $table->timestamp('restored_at')->nullable();

                $table->timestamps();
            });
        }

        if (! Schema::hasTable('security_finding_events')) {
            Schema::create('security_finding_events', function (Blueprint $table) use ($usersTable, $hasUsers) {
                $table->id();
                $table->foreignId('finding_id')->constrained('security_findings')->cascadeOnDelete();
                
                $uCol = $table->foreignId('user_id')->nullable();
                if ($hasUsers) {
                    $uCol->constrained($usersTable)->nullOnDelete();
                }

                $table->string('action', 40);
                $table->text('note')->nullable();
                $table->json('meta')->nullable();
                $table->string('ip', 45)->nullable();
                $table->timestamps();
            });
        }
    }

    public function down(): void
    {
        Schema::dropIfExists('security_finding_events');
        Schema::dropIfExists('security_quarantine');
        Schema::dropIfExists('security_findings');
        Schema::dropIfExists('security_file_inventory');
        Schema::dropIfExists('security_scan_runs');
    }
};