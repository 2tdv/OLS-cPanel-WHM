<?php
declare(strict_types=1);

namespace OlsCpanel\Events;

use OlsCpanel\Ols\Generation\Engine;

/**
 * The engine of the service loop (`sync --watch`), with the restriction deadline enforcement interleaved:
 * PHP has no threads, so the lab's 5-second enforcement thread (ols_events.enforcement_loop) becomes a
 * check before every engine operation and between the loop's one-second sleeps. A reconcile pass is a
 * sequence of engine operations (one per cPanel input read, then apply), so enforcement runs at least every
 * ENFORCE_EVERY seconds, except while one operation is in flight: one command read (at most 120 s, the
 * engine.run limit) or one apply (validation at most 60 s plus an activation with its bounded reload,
 * verification and rollback waits). Compilation as a whole never delays enforcement; a single operation
 * delays it by less than HR-D11's 300 s grace.
 */
final class PacedEngine implements Engine
{
    public const ENFORCE_EVERY = 5;
    public const GRACE = 300;

    private float $last = -INF;
    /** @var \Closure():float */
    private \Closure $clock;

    /**
     * @param \Closure(array<string,mixed>):void $emit receives enforcement actions and errors (one log line each)
     * @param (\Closure():float)|null $clock seconds, monotonic
     */
    public function __construct(private readonly Engine $inner, private readonly \Closure $emit, ?\Closure $clock = null)
    {
        $this->clock = $clock ?? static fn(): float => hrtime(true) / 1e9;
    }

    /**
     * Ask the activator to enforce the deadline when the last enforcement is ENFORCE_EVERY seconds old, after
     * folding the hook's restriction intents into the epoch (the broker's enforcement thread does both on its
     * own; here they also run for the root `sync --watch` on the local engine).
     */
    public function enforceIfDue(): void
    {
        if (($this->clock)() - $this->last < self::ENFORCE_EVERY) {
            return;
        }
        $this->last = ($this->clock)();
        try {
            $folded = $this->inner->foldRestrictions();
            if ($folded['folded'] !== []) {
                ($this->emit)(['time' => microtime(true), 'restrictions_folded' => $folded['folded'], 'epoch' => $folded['epoch']]);
            }
        } catch (\Throwable $error) {
            ($this->emit)(['time' => microtime(true), 'fold_error' => substr((new \ReflectionClass($error))->getShortName()
                . ': ' . $error->getMessage(), 0, 300)]);
        }
        try {
            $enforced = $this->inner->enforce(self::GRACE)['result'] ?? null;
            if ($enforced !== null && $enforced !== 'within-grace') {
                ($this->emit)(['time' => microtime(true), 'enforced' => $enforced]);
            }
        } catch (\Throwable $error) {
            ($this->emit)(['time' => microtime(true), 'enforce_error' => substr((new \ReflectionClass($error))->getShortName()
                . ': ' . $error->getMessage(), 0, 300)]);
        }
    }

    public function run(string $name, array $argv, int $timeout): array
    {
        $this->enforceIfDue();
        return $this->inner->run($name, $argv, $timeout);
    }

    public function apply(string $generation, array $files, array $health, int $epoch, string $sourceSha256): array
    {
        $this->enforceIfDue();
        return $this->inner->apply($generation, $files, $health, $epoch, $sourceSha256);
    }

    public function status(): array
    {
        $this->enforceIfDue();
        return $this->inner->status();
    }

    public function health(int $seconds): array
    {
        $this->enforceIfDue();
        return $this->inner->health($seconds);
    }

    public function enforce(int $grace): array
    {
        return $this->inner->enforce($grace);
    }

    public function recover(int $grace): array
    {
        $this->enforceIfDue();
        return $this->inner->recover($grace);
    }

    public function pendingEvents(): array
    {
        $this->enforceIfDue();
        return $this->inner->pendingEvents();
    }

    public function eventsDone(array $names): array
    {
        $this->enforceIfDue();
        return $this->inner->eventsDone($names);
    }

    public function eventsQuarantine(array $names): array
    {
        $this->enforceIfDue();
        return $this->inner->eventsQuarantine($names);
    }

    public function foldRestrictions(): array
    {
        $this->enforceIfDue();
        return $this->inner->foldRestrictions();
    }
}
