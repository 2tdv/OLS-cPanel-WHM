<?php
declare(strict_types=1);

namespace OlsCpanel\Cli\Command;

use OlsCpanel\Cli\Application;
use OlsCpanel\Cli\Arguments;
use OlsCpanel\Cli\Command;
use OlsCpanel\Cli\EngineContext;
use OlsCpanel\Cli\Output;
use OlsCpanel\Cli\Refused;
use OlsCpanel\Cli\UsageError;
use OlsCpanel\Deployment\Environment;
use OlsCpanel\Operations\LoginGuard;

/**
 * `login-guard status|set|unblock|run` (RV-64, CMP-04; root): the WordPress login guard. `run` is ols-cpanel-login-guard.service
 * (a pass every five seconds; `--once` for one pass); `set --enabled=yes|no` is what the WHM switch calls, `--allow=<address or
 * range>,...|none` the operator's own never-blocked list; `unblock --address=<ip> [--domain=<site>]` lifts a block at once.
 */
final class LoginGuardCommand implements Command
{
    public const ACTIONS = ['status' => 'Show the login guard: switch, limits, blocked addresses', 'set' => 'Set --enabled=yes|no --allow=a,b|none',
        'unblock' => 'Lift the block of --address=<ip> [--domain=<site>]', 'run' => 'Watch the access logs and block login floods (the service; --once for one pass)'];

    /** @param (\Closure():LoginGuard)|null $factory */
    public function __construct(private readonly EngineContext $context, private readonly string $action, private readonly ?\Closure $factory = null,
                                private readonly string $state = Environment::STATE)
    {
    }

    public function words(): array
    {
        return ['login-guard', $this->action];
    }

    public function summary(): string
    {
        return self::ACTIONS[$this->action] . ' (root)';
    }

    public function run(array $argv, Output $out): int
    {
        $args = new Arguments($argv, $this->action === 'run' ? ['once'] : [], match ($this->action) {
            'set' => ['enabled', 'allow'], 'unblock' => ['address', 'domain'], default => [] });
        $this->context->root();
        $guard = fn(): LoginGuard => $this->factory !== null ? ($this->factory)() : new LoginGuard($this->state);
        $now = time();
        $result = ['command' => 'login-guard ' . $this->action];
        switch ($this->action) {
            case 'set':
                $enabled = $args->value('enabled');
                $allow = $args->value('allow');
                if ($enabled === null && $allow === null) {
                    throw new UsageError('set needs --enabled=yes|no or --allow=<addresses>|none');
                }
                if ($enabled !== null && !in_array($enabled, ['yes', 'no'], true)) {
                    throw new UsageError('--enabled must be yes or no');
                }
                try {
                    LoginGuard::saveSettings($this->state, $enabled === null ? null : $enabled === 'yes',
                        $allow === null ? null : ($allow === 'none' ? [] : explode(',', $allow)), $now);
                } catch (Refused $error) {
                    throw new UsageError($error->getMessage());
                }
                // The map follows at once (off empties it), not only on the watcher's next pass.
                $guard()->pass($now);
                $result['changed'] = true;
                break;
            case 'unblock':
                $address = $args->value('address');
                $domain = $args->value('domain');
                if ($address === null || filter_var($address, FILTER_VALIDATE_IP) === false) {
                    throw new UsageError('unblock needs --address=<ip>');
                }
                if ($domain !== null && preg_match('/^[a-z0-9][a-z0-9.-]{0,252}$/D', $domain) !== 1) {
                    throw new UsageError('--domain must be a site name');
                }
                $result['removed'] = $guard()->unblock($address, $domain, $now);
                break;
            case 'run':
                if (!$args->flag('once')) {
                    $guard()->watch();
                    return Application::EXIT_OK;
                }
                $result['pass'] = $guard()->pass($now);
                break;
        }
        $out->result($result + $guard()->status($now));
        return Application::EXIT_OK;
    }
}
