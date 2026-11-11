<?php
declare(strict_types=1);

namespace OlsCpanel\Events;

/**
 * The inputs of a compile could not be digested completely (InputDigest: a listing failed, a path is unsafe, a file cannot
 * be stat'ed). Never an error of the pass: the Reconciler compiles instead of skipping, so nothing is ever left stale on a guess.
 */
final class InputsUnsure extends \RuntimeException
{
}
