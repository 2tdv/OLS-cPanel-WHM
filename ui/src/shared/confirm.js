// Typed confirmation (UIX-03): the exact expected text, surrounding spaces ignored, never an empty match.
export function confirmationMatches(typed, expected) {
  return typeof expected === 'string' && expected !== '' && String(typed ?? '').trim() === expected
}
