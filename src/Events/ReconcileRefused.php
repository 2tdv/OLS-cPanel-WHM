<?php
declare(strict_types=1);

namespace OlsCpanel\Events;

/**
 * Reconciliation may not run: the server is not cut over (no profile.json), the profile is malformed or
 * not a production profile, or the restriction epoch is unknown. Nothing was compiled or changed.
 */
final class ReconcileRefused extends \RuntimeException
{
}
