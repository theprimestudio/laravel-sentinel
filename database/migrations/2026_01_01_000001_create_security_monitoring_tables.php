<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        if (! Schema::hasTable('security_audits')) {
            Schema::create('security_audits', function (Blueprint $table) {
                $table->id();
                $table->string('environment');
                $table->string('status');
                $table->integer('score')->default(0);
                $table->json('result_json')->nullable();
                $table->timestamps();
            });
        }

        if (! Schema::hasTable('security_alerts')) {
            Schema::create('security_alerts', function (Blueprint $table) {
                $table->id();
                $table->string('severity');
                $table->string('title');
                $table->text('description');
                $table->timestamp('resolved_at')->nullable();
                $table->timestamps();
            });
        }
    }

    public function down(): void
    {
        Schema::dropIfExists('security_alerts');
        Schema::dropIfExists('security_audits');
    }
};