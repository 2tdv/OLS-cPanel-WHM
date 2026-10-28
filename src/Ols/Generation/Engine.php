<?php
declare(strict_types=1);

namespace OlsCpanel\Ols\Generation;

use OlsCpanel\Infrastructure\Process\CommandRunner;

/**
 * The privileged half of the engine (docs/product-interfaces.md, engine socket): cPanel input reads,
 * generation activation, deadline enforcement, recovery and the event spool. BrokerEngine reaches it
 * through engine.sock (the reconciler as `olscpanel`); LocalEngine performs it directly (root CLI).
 * Results are the activator's own JSON objects. Failures of the engine itself are EngineError with the
 * broker's error code (FORBIDDEN, BAD_ARGS, TIMEOUT, OUTPUT_TOO_LARGE, SPAWN_FAILED, EXISTS, NOT_FOUND,
 * ACTIVATOR, TOO_LARGE, INTERNAL, BROKER_UNAVAILABLE, BROKER_REPLY), whichever implementation runs.
 */
interface Engine extends CommandRunner
{
    /**
     * Stage, validate and activate a generation built by GenerationTree.
     * @param string $generation new generation id, `r<YYYYmmddHHMMSS>-<6 hex>`
     * @param array<string,string> $files relative path => content (httpd_config.conf, summary.json, vhosts/<v>/vhconf.conf, health/<v>/id, marker/generation)
     * @param list<array{vhost:string,host:string,url:string}> $health
     * @return array{generation:string, valid:bool, result:string, reason:mixed}
     */
    public function apply(string $generation, array $files, array $health, int $epoch, string $sourceSha256): array;

    /** @return array<string,mixed> activator status plus "source_sha256" of the active generation (or null) */
    public function status(): array;

    /**
     * Vhost health of the active generation (activator `health --seconds N`, engine.health): every target of
     * its health.json answered with this generation's id within `seconds`, or the failures.
     * @return array{generation:?string, failing:list<array<string,mixed>>}
     */
    public function health(int $seconds): array;

    /** @return array<string,mixed> */
    public function enforce(int $grace): array;

    /** @return array<string,mixed> */
    public function recover(int $grace): array;

    /**
     * Pending spool entries, oldest first (at most 1000); an unreadable or malformed entry carries "error"
     * instead of "event".
     * @return list<array{name:string, event?:array<string,mixed>, error?:string}>
     */
    public function pendingEvents(): array;

    /**
     * Move spool entries to done/ (all or nothing: an unknown name is NOT_FOUND, a repeated or malformed
     * one BAD_ARGS).
     * @param list<string> $names
     * @return list<string> the names moved
     */
    public function eventsDone(array $names): array;

    /**
     * Move malformed spool entries (names as pendingEvents() lists them, with "error") to events/quarantine/
     * (engine.events_quarantine), so they never block the consumption of valid entries (review RV-29,
     * finding 16). All or nothing like eventsDone: a name that is not one directory entry of the spool is
     * BAD_ARGS, an absent one NOT_FOUND.
     * @param list<string> $names
     * @return list<string> the names moved
     */
    public function eventsQuarantine(array $names): array;

    /**
     * Fold every durable restriction intent (STATE/restrictions/, written by the hook when it could not raise
     * the epoch; review RV-29, finding 5) into the restriction epoch, oldest first: the epoch is raised durably
     * (activator `restrict`), and only then is the intent removed (engine.restrictions_fold).
     * @return array{folded:list<string>, epoch:?int} the intents folded and the epoch after the last one
     */
    public function foldRestrictions(): array;
}
