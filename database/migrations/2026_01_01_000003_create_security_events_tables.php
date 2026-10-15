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

        if (! Schema::hasTable('security_incidents')) {
            Schema::create('security_incidents', function (Blueprint $table) use ($usersTable, $hasUsers) {
                $table->id();
                $table->char('fingerprint', 64)->index();
                $table->string('type', 40)->index();
                $table->string('severity', 10)->index();
                $table->string('title');
                $table->string('status', 20)->default('open')->index();

                $aCol = $table->foreignId('assigned_to')->nullable();
                if ($hasUsers) {
                    $aCol->constrained($usersTable)->nullOnDelete();
                }

                $table->string('source_ip', 45)->nullable()->index();
                $table->unsignedInteger('event_count')->default(0);
                $table->unsignedInteger('suppressed_count')->default(0);
                $table->timestamp('first_seen_at')->nullable();
                $table->timestamp('last_seen_at')->nullable()->index();
                $table->timestamp('notified_at')->nullable();

                $rCol = $table->foreignId('resolved_by')->nullable();
                if ($hasUsers) {
                    $rCol->constrained($usersTable)->nullOnDelete();
                }
                $table->timestamp('resolved_at')->nullable();

                $table->timestamps();
            });
        }

        if (! Schema::hasTable('security_events')) {
            Schema::create('security_events', function (Blueprint $table) use ($usersTable, $hasUsers) {
                $table->id();
                $table->timestamp('occurred_at')->index();
                $table->string('type', 40)->index();
                $table->string('severity', 10)->index();
                $table->string('source_ip', 45)->nullable()->index();

                $uCol = $table->foreignId('user_id')->nullable();
                if ($hasUsers) {
                    $uCol->constrained($usersTable)->nullOnDelete();
                }

                $table->string('method', 10)->nullable();
                $table->string('route', 191)->nullable()->index();
                $table->string('path', 500)->nullable();
                $table->text('reason');
                $table->string('action', 20)->default('logged');
                $table->json('context')->nullable();
                $table->char('fingerprint', 64)->index();
                $table->foreignId('incident_id')->nullable()->constrained('security_incidents')->nullOnDelete();
                $table->char('prev_hash', 64)->nullable();
                $table->char('hash', 64);
                $table->timestamp('created_at')->nullable();
            });
        }

        if (! Schema::hasTable('security_incident_notes')) {
            Schema::create('security_incident_notes', function (Blueprint $table) use ($usersTable, $hasUsers) {
                $table->id();
                $table->foreignId('incident_id')->constrained('security_incidents')->cascadeOnDelete();

                $uCol = $table->foreignId('user_id')->nullable();
                if ($hasUsers) {
                    $uCol->constrained($usersTable)->nullOnDelete();
                }

                $table->string('action', 40);
                $table->text('note')->nullable();
                $table->json('meta')->nullable();
                $table->string('ip', 45)->nullable();
                $table->timestamp('created_at')->nullable();
            });
        }

        if (! Schema::hasTable('security_content_backups')) {
            Schema::create('security_content_backups', function (Blueprint $table) use ($usersTable, $hasUsers) {
                $table->id();
                $table->foreignId('finding_id')->nullable()->constrained('security_findings')->nullOnDelete();
                $table->string('table_name', 64);
                $table->string('record_key', 64);
                $table->string('field', 191);
                $table->longText('original');
                $table->longText('sanitized');
                $table->char('original_sha256', 64);

                $aCol = $table->foreignId('applied_by')->nullable();
                if ($hasUsers) {
                    $aCol->constrained($usersTable)->nullOnDelete();
                }
                $table->timestamp('applied_at')->nullable();

                $rCol = $table->foreignId('restored_by')->nullable();
                if ($hasUsers) {
                    $rCol->constrained($usersTable)->nullOnDelete();
                }
                $table->timestamp('restored_at')->nullable();

                $table->timestamps();
            });
        }

        if (! Schema::hasTable('security_txt')) {
            Schema::create('security_txt', function (Blueprint $table) use ($usersTable, $hasUsers) {
                $table->id();
                $table->text('contacts');
                $table->timestamp('expires_at');
                $table->text('encryption')->nullable();
                $table->text('acknowledgments')->nullable();
                $table->string('preferred_languages')->nullable();
                $table->text('policy')->nullable();
                $table->text('hiring')->nullable();
                $table->text('canonical')->nullable();

                $uCol = $table->foreignId('updated_by')->nullable();
                if ($hasUsers) {
                    $uCol->constrained($usersTable)->nullOnDelete();
                }

                $table->timestamps();
            });
        }
    }

    public function down(): void
    {
        Schema::dropIfExists('security_txt');
        Schema::dropIfExists('security_content_backups');
        Schema::dropIfExists('security_incident_notes');
        Schema::dropIfExists('security_events');
        Schema::dropIfExists('security_incidents');
    }
};