<?php
declare(strict_types=1);

namespace OlsCpanel\Events;

/** Another reconciliation holds the reconcile lock (CLI exit 75). */
final class ReconcileBusy extends \RuntimeException
{
}
