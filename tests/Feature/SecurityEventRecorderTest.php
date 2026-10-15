<?php

namespace ThePrimeStudio\LaravelSentinel\Tests\Feature;

use ThePrimeStudio\LaravelSentinel\Models\SecurityEvent;
use ThePrimeStudio\LaravelSentinel\Services\SecurityEventRecorder;
use ThePrimeStudio\LaravelSentinel\Tests\TestCase;

class SecurityEventRecorderTest extends TestCase
{
    public function test_records_event_with_hash_chain(): void
    {
        $recorder = app(SecurityEventRecorder::class);

        $event1 = $recorder->record('exploit_attempt', 'high', 'SQL injection test', ['password' => 'secret123'], 'blocked', '127.0.0.1');
        $this->assertNotNull($event1);
        $this->assertNotEmpty($event1->hash);
        $this->assertEquals('[REDACTED]', $event1->context['password'] ?? null);

        $event2 = $recorder->record('failed_login', 'low', 'Failed login attempt', [], 'logged', '127.0.0.1');
        $this->assertNotNull($event2);
        $this->assertEquals($event1->hash, $event2->prev_hash);

        // Verify chain
        $verification = $recorder->verifyChain(10);
        $this->assertTrue($verification['ok']);
    }
}