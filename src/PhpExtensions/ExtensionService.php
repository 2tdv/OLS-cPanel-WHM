<?php
declare(strict_types=1);

namespace OlsCpanel\PhpExtensions;

/** What the object cache commands and the `php-ext` CLI need from the extension layer (injectable in tests). */
interface ExtensionService
{
    /** Read-only report (see ExtensionInstaller::status), with `needs_sync`. @return array<string,mixed> */
    public function status(): array;

    /** Brings the given EA4 PHP versions of an account to a loading redis; restarts that account's lsphp when something changed. @return array<string,mixed> */
    public function ensureForAccount(string $user, array $versions): array;

    /**
     * The PHP environment applier's step: brings the given installed versions to a loading redis now (the applier
     * owns the back-off) and restarts the lsphp of the accounts on a version that changed. @return array<string,mixed>
     * @param list<string> $versions
     */
    public function ensureVersions(array $versions): array;

    /** The watcher's pass over every installed version. @return array<string,mixed> */
    public function sync(): array;

    /** Operator install of every version, or one. @return array<string,mixed> */
    public function install(?string $only): array;

    /** @return array<string,mixed> */
    public function remove(): array;

    /** Marks the extension wanted and enables the watcher (the object cache is in use). */
    public function want(): void;
}
