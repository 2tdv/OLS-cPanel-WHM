<?php
declare(strict_types=1);

namespace OlsCpanel\Operations;

use OlsCpanel\Cli\Refused;

/**
 * The notification settings (FV-07): `<state>/notify.json`, root 0600. Opt-in: nothing is sent until at least one e-mail address
 * or a webhook is set. The webhook URL may carry a secret (many services put the token in the path), so it is never shown again,
 * never logged and never returned by any view; the views show whether it is set and its host name only.
 */
final class NotifySettings
{
    public const FILE = 'notify.json';
    public const MAX_EMAILS = 5;
    public const MAX_URL = 512;
    /** event key => what it covers */
    public const EVENTS = [
        'job' => 'A switch, return or recovery job finished',
        'held' => 'A site was newly held back or left on Apache',
        'php_env' => 'A PHP environment check failed',
        'upgrade' => 'An upgrade failed',
        'cache_emergency' => 'The page cache was trimmed in an emergency',
        'disk' => 'A disk is nearly full',
        'objcache' => 'An object cache site check failed',
        'schedule' => 'A scheduled job was missed or could not start',
    ];

    /** @param list<string> $emails @param list<string> $events */
    public function __construct(public readonly array $emails = [], public readonly ?string $webhook = null,
                                public readonly array $events = [], public readonly int $enabledSince = 0)
    {
    }

    public static function validEmail(string $address): bool
    {
        return strlen($address) <= 254 && !str_contains($address, '..')
            && preg_match('/^[A-Za-z0-9][A-Za-z0-9._%+-]{0,63}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/D', $address) === 1;
    }

    /** https only, a host name (no credentials, no spaces or quotes), bounded. */
    public static function validWebhook(string $url): bool
    {
        if (strlen($url) > self::MAX_URL || preg_match('/^https:\/\/[A-Za-z0-9._~:\/?#@!$&()*+,;=%-]+$/D', $url) !== 1) {
            return false;
        }
        $parts = parse_url($url);
        if (!is_array($parts) || ($parts['scheme'] ?? '') !== 'https' || isset($parts['user']) || isset($parts['pass'])
            || !is_string($parts['host'] ?? null) || preg_match('/^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$/D', $parts['host']) !== 1) {
            return false;
        }
        return !isset($parts['port']) || ($parts['port'] >= 1 && $parts['port'] <= 65535);
    }

    public static function load(string $state): self
    {
        $data = StateFile::read($state . '/' . self::FILE) ?? [];
        $emails = array_values(array_filter(is_array($data['emails'] ?? null) ? $data['emails'] : [],
            static fn($a): bool => is_string($a) && self::validEmail($a)));
        $webhook = is_string($data['webhook'] ?? null) && self::validWebhook($data['webhook']) ? $data['webhook'] : null;
        $events = array_values(array_filter(is_array($data['events'] ?? null) ? $data['events'] : array_keys(self::EVENTS),
            static fn($e): bool => is_string($e) && isset(self::EVENTS[$e])));
        return new self(array_slice($emails, 0, self::MAX_EMAILS), $webhook, $events, is_int($data['enabled_since'] ?? null) ? $data['enabled_since'] : 0);
    }

    public function enabled(): bool
    {
        return $this->emails !== [] || $this->webhook !== null;
    }

    public function wants(string $event): bool
    {
        return in_array($event, $this->events, true);
    }

    /**
     * Validates and writes the settings. $webhook: null keeps the stored URL, '' removes it.
     * @param list<string> $emails
     * @param list<string>|null $events null keeps the stored selection
     */
    public static function save(string $state, array $emails, ?string $webhook, ?array $events, int $now): self
    {
        $old = self::load($state);
        $emails = array_values(array_unique(array_map('strtolower', $emails)));
        if (count($emails) > self::MAX_EMAILS) {
            throw new Refused('at most ' . self::MAX_EMAILS . ' e-mail addresses');
        }
        foreach ($emails as $address) {
            if (!self::validEmail($address)) {
                throw new Refused('not a valid e-mail address');
            }
        }
        if ($webhook !== null && $webhook !== '' && !self::validWebhook($webhook)) {
            throw new Refused('the webhook must be an https URL without credentials (at most ' . self::MAX_URL . ' characters)');
        }
        $url = $webhook === null ? $old->webhook : ($webhook === '' ? null : $webhook);
        $events = $events ?? $old->events;
        foreach ($events as $event) {
            if (!isset(self::EVENTS[$event])) {
                throw new Refused('unknown event');
            }
        }
        $events = array_values(array_unique($events));
        $enabled = $emails !== [] || $url !== null;
        $since = !$enabled ? 0 : ($old->enabled() ? $old->enabledSince : $now);
        StateFile::write($state . '/' . self::FILE, ['emails' => $emails, 'webhook' => $url, 'events' => $events,
            'enabled_since' => $since, 'updated_at' => $now]);
        return new self($emails, $url, $events, $since);
    }

    /** The settings as a view: the webhook is reduced to its host name. @return array<string,mixed> */
    public function view(): array
    {
        $host = $this->webhook === null ? null : (string) parse_url($this->webhook, PHP_URL_HOST);
        return ['enabled' => $this->enabled(), 'emails' => $this->emails, 'webhook' => ['set' => $this->webhook !== null, 'host' => $host],
            'events' => $this->events, 'available_events' => self::EVENTS, 'enabled_since' => $this->enabledSince ?: null];
    }
}
