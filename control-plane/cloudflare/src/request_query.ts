/**
 * Shape-only query validation for Owner HTTP routes. Exactly one occurrence
 * of each required key is allowed: no ignored model-supplied owner/Space IDs,
 * aliases, repeated parameters or silent first-value selection.
 *
 * This is NOT authorization; signed Owner identity and canonical PostgreSQL
 * RPCs remain the only sources of access authority.
 */
export function hasExactQueryParameters(url: URL, required: readonly string[]): boolean {
  const expected = new Set(required);
  const actual = [...url.searchParams.keys()];
  if (expected.size !== required.length || actual.length !== required.length) return false;
  const seen = new Set<string>();
  for (const name of actual) {
    if (!expected.has(name) || seen.has(name)) return false;
    seen.add(name);
  }
  return true;
}
