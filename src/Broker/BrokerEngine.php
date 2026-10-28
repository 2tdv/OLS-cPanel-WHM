<?php
declare(strict_types=1);

namespace OlsCpanel\Broker;

use OlsCpanel\Ols\Generation\Engine;
use OlsCpanel\Ols\Generation\EngineError;

/**
 * The engine over engine.sock (the reconciler as `olscpanel`): every operation is one broker request
 * (docs/product-interfaces.md, engine socket). The broker enforces its own limits (engine.run: allowlist,
 * 120 s, 16 MiB); the client only waits long enough for the slowest operation (an activation that
 * reloads OLS, verifies every vhost and may roll back). Broker errors become EngineError with the
 * broker's code preserved (FORBIDDEN, BAD_ARGS, TIMEOUT, OUTPUT_TOO_LARGE, SPAWN_FAILED, EXISTS, NOT_FOUND,
 * ACTIVATOR, TOO_LARGE; BROKER_UNAVAILABLE / BROKER_REPLY from the client).
 */
final class BrokerEngine implements Engine
{
    private const TIMEOUT = 900.0;

    private BrokerClient $client;

    public function __construct(?BrokerClient $client = null)
    {
        $this->client = $client ?? new BrokerClient(BrokerClient::ENGINE_SOCKET, self::TIMEOUT, BrokerClient::MAX_ENGINE_REPLY);
    }

    public function run(string $name, array $argv, int $timeout): array
    {
        $result = $this->call('engine.run', ['name' => $name, 'argv' => $argv]);
        if (!is_int($result['exit_code'] ?? null) || !is_string($result['stdout'] ?? null)) {
            throw new EngineError('BROKER_REPLY', 'engine.run returned no command result');
        }
        return ['exit_code' => $result['exit_code'], 'stdout' => $result['stdout'], 'stderr' => (string) ($result['stderr'] ?? '')];
    }

    public function apply(string $generation, array $files, array $health, int $epoch, string $sourceSha256): array
    {
        $result = $this->call('engine.apply', ['generation' => $generation, 'files' => (object) $files, 'health' => $health,
            'epoch' => $epoch, 'source_sha256' => $sourceSha256]);
        if (!is_bool($result['valid'] ?? null) || !is_string($result['result'] ?? null)) {
            throw new EngineError('BROKER_REPLY', 'engine.apply returned no activation result');
        }
        return ['generation' => (string) ($result['generation'] ?? $generation), 'valid' => $result['valid'],
            'result' => $result['result'], 'reason' => $result['reason'] ?? null];
    }

    public function status(): array
    {
        return $this->call('engine.status');
    }

    public function health(int $seconds): array
    {
        $result = $this->call('engine.health', ['seconds' => max(0, min(60, $seconds))]);
        if (!array_key_exists('generation', $result) || !is_array($result['failing'] ?? null)) {
            throw new EngineError('BROKER_REPLY', 'engine.health returned no health result');
        }
        return $result;
    }

    public function enforce(int $grace): array
    {
        return $this->call('engine.enforce', ['grace' => max(0, $grace)]);
    }

    public function recover(int $grace): array
    {
        return $this->call('engine.recover', ['grace' => max(0, $grace)]);
    }

    public function pendingEvents(): array
    {
        $pending = $this->call('engine.events')['pending'] ?? null;
        if (!is_array($pending) || !array_is_list($pending)) {
            throw new EngineError('BROKER_REPLY', 'engine.events returned no spool list');
        }
        $out = [];
        foreach ($pending as $entry) {
            if (!is_array($entry) || !is_string($entry['name'] ?? null)) {
                throw new EngineError('BROKER_REPLY', 'malformed spool entry');
            }
            $out[] = is_array($entry['event'] ?? null) ? ['name' => $entry['name'], 'event' => $entry['event']]
                : ['name' => $entry['name'], 'error' => is_string($entry['error'] ?? null) ? $entry['error'] : 'malformed spool entry'];
        }
        return $out;
    }

    public function eventsDone(array $names): array
    {
        $done = $this->call('engine.events_done', ['names' => array_values($names)])['done'] ?? null;
        if (!is_array($done) || !array_is_list($done)) {
            throw new EngineError('BROKER_REPLY', 'engine.events_done returned no list');
        }
        return array_map('strval', $done);
    }

    public function eventsQuarantine(array $names): array
    {
        $moved = $this->call('engine.events_quarantine', ['names' => array_values($names)])['quarantined'] ?? null;
        if (!is_array($moved) || !array_is_list($moved)) {
            throw new EngineError('BROKER_REPLY', 'engine.events_quarantine returned no list');
        }
        return array_map('strval', $moved);
    }

    public function foldRestrictions(): array
    {
        $result = $this->call('engine.restrictions_fold');
        $folded = $result['folded'] ?? null;
        $epoch = $result['epoch'] ?? null;
        if (!is_array($folded) || !array_is_list($folded) || !(is_int($epoch) || $epoch === null)) {
            throw new EngineError('BROKER_REPLY', 'engine.restrictions_fold returned no fold result');
        }
        return ['folded' => array_map('strval', $folded), 'epoch' => $epoch];
    }

    /** @return array<string,mixed> */
    private function call(string $op, ?array $args = null): array
    {
        $reply = $this->client->call($op, $args);
        if (($reply['ok'] ?? false) !== true) {
            $error = is_array($reply['error'] ?? null) ? $reply['error'] : [];
            throw new EngineError((string) ($error['code'] ?? 'BROKER_REPLY'), "$op: " . (string) ($error['message'] ?? 'failed'));
        }
        $result = $reply['result'] ?? null;
        if (!is_array($result)) {
            throw new EngineError('BROKER_REPLY', "$op returned no object");
        }
        return $result;
    }
}
