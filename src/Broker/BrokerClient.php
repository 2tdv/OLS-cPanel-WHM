<?php
declare(strict_types=1);

namespace OlsCpanel\Broker;

/**
 * Client for the ols-cpanel-broker sockets (plan 5.3-5.4): one versioned JSON request per connection,
 * bounded reply size and time. Callers never pass identities: the admin socket is root-only and the
 * tenant socket identifies the account from the kernel peer credentials. The engine socket carries large
 * requests (engine.apply) and replies (compiler inputs, up to 32 MiB), so its client raises the reply
 * limit and the time limit; requests are written completely (a socket write may be partial).
 */
final class BrokerClient
{
    public const ADMIN_SOCKET = '/run/ols-cpanel-broker/admin.sock';
    public const TENANT_SOCKET = '/run/ols-cpanel-broker/tenant.sock';
    public const ENGINE_SOCKET = '/run/ols-cpanel-broker/engine.sock';
    public const MAX_REPLY = 4 * 1024 * 1024;
    public const MAX_ENGINE_REPLY = 32 * 1024 * 1024;

    public function __construct(private readonly string $socket, private readonly float $timeout = 5.0,
                                private readonly int $maxReply = self::MAX_REPLY)
    {
    }

    /** @return array{ok:bool,result?:mixed,error?:array{code:string,message:string}} */
    public function call(string $op, ?array $args = null): array
    {
        $request = ['v' => 1, 'id' => bin2hex(random_bytes(8)), 'op' => $op];
        if ($args !== null) {
            $request['args'] = $args;
        }
        $stream = @stream_socket_client('unix://' . $this->socket, $errno, $errstr, min($this->timeout, 5.0));
        if ($stream === false) {
            return ['ok' => false, 'error' => ['code' => 'BROKER_UNAVAILABLE', 'message' => 'The OLS-cPanel service is not available.']];
        }
        stream_set_timeout($stream, (int) ceil($this->timeout));
        $line = json_encode($request, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . "\n";
        for ($sent = 0; $sent < strlen($line); $sent += $written) {
            $written = @fwrite($stream, substr($line, $sent, 1048576));
            if ($written === false || $written === 0) {
                fclose($stream);
                return ['ok' => false, 'error' => ['code' => 'BROKER_REPLY', 'message' => 'The request could not be sent.']];
            }
        }
        $reply = '';
        while (!feof($stream) && strlen($reply) <= $this->maxReply && !str_ends_with($reply, "\n")) {
            $chunk = fread($stream, 65536);
            if ($chunk === false || ($chunk === '' && stream_get_meta_data($stream)['timed_out'])) {
                break;
            }
            $reply .= $chunk;
        }
        fclose($stream);
        $decoded = strlen($reply) > $this->maxReply ? null : json_decode(trim($reply), true, 512);
        // Early broker errors (before the request is parsed) carry no id; a success must echo ours.
        $unexpected = !is_array($decoded) || !is_bool($decoded['ok'] ?? null)
            || ($decoded['ok'] === true && ($decoded['id'] ?? null) !== $request['id']);
        if ($unexpected) {
            return ['ok' => false, 'error' => ['code' => 'BROKER_REPLY', 'message' => 'Unexpected reply from the OLS-cPanel service.']];
        }
        return $decoded;
    }
}
