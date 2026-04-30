/**
 * Logging / audit / metric / OTel scrubber. SPEC §6.6 + RT-44.
 *
 * Three layers of redaction, applied in order:
 *   1. Key-name match: any record key whose name matches the configured
 *      key-name patterns (authorization, token, secret, …) → "[REDACTED:KEY]".
 *   2. Value pattern match: known secret prefixes (agk_, ghp_, sk-ant-, sk-…)
 *      anywhere in a string → "[REDACTED:PATTERN]".
 *   3. High-entropy heuristic: a string with Shannon entropy ≥
 *      `high_entropy_threshold` (default 4.5 bits/char) AND length ≥
 *      `min_high_entropy_length` (default 24) → "[REDACTED:ENTROPY]".
 *
 * Plus structural caps:
 *   - max_jsonb_depth (default 4): arrays/objects deeper than this become "[TRUNCATED:DEPTH]".
 *   - max_string_length (default 1024): strings get sliced + suffixed "...[TRUNCATED:LEN]".
 *   - max_serialized_size_kb (default 4): final JSON.stringify is hard-capped;
 *     overflow becomes a flat object with a marker.
 *
 * The scrubber is intentionally conservative — it errs on the side of
 * over-redaction. Unit tests cover each rule.
 */

const DEFAULT_VALUE_PATTERNS: ReadonlyArray<RegExp> = [
  /agk_[A-Za-z0-9_-]{1,32}\.[A-Za-z0-9_-]{20,128}/g, // our keys (wire form)
  /ghp_[A-Za-z0-9]{36,}/g, // GitHub PAT
  /github_pat_[A-Za-z0-9_]+/g, // GitHub fine-grained
  /sk-ant-[A-Za-z0-9-]+/g, // Anthropic
  /sk-[A-Za-z0-9]{40,}/g, // OpenAI
];

const DEFAULT_KEY_PATTERNS: ReadonlyArray<RegExp> = [
  /authorization/i,
  /\btoken\b/i,
  /\bsecret\b/i,
  /\bpassword\b/i,
  /\bcookie\b/i,
  /\bcredential/i,
  /\bprivate/i,
  /\bkey$/i,
];

export interface ScrubberConfig {
  readonly high_entropy_threshold?: number; // bits per char
  readonly min_high_entropy_length?: number; // skip short strings
  readonly max_string_length?: number;
  readonly max_jsonb_depth?: number;
  readonly max_serialized_size_kb?: number;
  readonly extra_value_patterns?: ReadonlyArray<RegExp>;
  readonly extra_key_patterns?: ReadonlyArray<RegExp>;
}

export interface CompiledScrubber {
  scrub<T>(input: T): unknown;
  scrubLine(s: string): string;
}

interface Resolved {
  high_entropy_threshold: number;
  min_high_entropy_length: number;
  max_string_length: number;
  max_jsonb_depth: number;
  max_serialized_size_bytes: number;
  value_patterns: ReadonlyArray<RegExp>;
  key_patterns: ReadonlyArray<RegExp>;
}

export function buildScrubber(cfg: ScrubberConfig = {}): CompiledScrubber {
  const r: Resolved = {
    high_entropy_threshold: cfg.high_entropy_threshold ?? 4.5,
    min_high_entropy_length: cfg.min_high_entropy_length ?? 24,
    max_string_length: cfg.max_string_length ?? 1024,
    max_jsonb_depth: cfg.max_jsonb_depth ?? 4,
    max_serialized_size_bytes: (cfg.max_serialized_size_kb ?? 4) * 1024,
    value_patterns: [...DEFAULT_VALUE_PATTERNS, ...(cfg.extra_value_patterns ?? [])],
    key_patterns: [...DEFAULT_KEY_PATTERNS, ...(cfg.extra_key_patterns ?? [])],
  };
  return {
    scrub<T>(input: T): unknown {
      return cap(scrubValue(input, 0, r), r);
    },
    scrubLine(s: string): string {
      return scrubString(s, r);
    },
  };
}

function scrubValue(v: unknown, depth: number, r: Resolved): unknown {
  if (v === null || v === undefined) return v;
  if (typeof v === 'boolean' || typeof v === 'number') return v;
  // BigInts are commonly Postgres BIGSERIAL IDs that can exceed
  // Number.MAX_SAFE_INTEGER (2^53). Stringify to preserve precision —
  // Number() conversion would silently round huge IDs.
  if (typeof v === 'bigint') return v.toString();
  if (typeof v === 'string') return scrubString(v, r);
  if (Buffer.isBuffer(v)) {
    // Buffers are usually binary keys / hashes — never log raw.
    return `[REDACTED:BUFFER:${v.length}b]`;
  }
  if (v instanceof Date) return v.toISOString();
  if (Array.isArray(v)) {
    if (depth >= r.max_jsonb_depth) return '[TRUNCATED:DEPTH]';
    return v.map((x) => scrubValue(x, depth + 1, r));
  }
  if (typeof v === 'object') {
    if (depth >= r.max_jsonb_depth) return '[TRUNCATED:DEPTH]';
    const out: Record<string, unknown> = {};
    for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
      if (matchesKey(k, r.key_patterns)) {
        out[k] = '[REDACTED:KEY]';
        continue;
      }
      out[k] = scrubValue(val, depth + 1, r);
    }
    return out;
  }
  return String(v);
}

function scrubString(s: string, r: Resolved): string {
  // 1. Pattern-based redaction (line-wide so multi-pattern matches still work).
  let out = s;
  for (const re of r.value_patterns) {
    out = out.replace(re, '[REDACTED:PATTERN]');
  }
  // 2. Length cap.
  if (out.length > r.max_string_length) {
    out = out.slice(0, r.max_string_length) + '...[TRUNCATED:LEN]';
  }
  // 3. High-entropy heuristic. Apply per-token (split on whitespace) so a
  //    log line like "token: <base64>" still gets the secret token redacted
  //    without dropping the leading prose.
  if (/\s/.test(out)) {
    return out.replace(/\S+/g, (token) => maybeRedactEntropy(token, r));
  }
  return maybeRedactEntropy(out, r);
}

function maybeRedactEntropy(token: string, r: Resolved): string {
  if (token.length < r.min_high_entropy_length) return token;
  if (/REDACTED|TRUNCATED/.test(token)) return token;
  if (shannonEntropy(token) < r.high_entropy_threshold) return token;
  if (!isLikelySecretShape(token)) return token;
  return '[REDACTED:ENTROPY]';
}

function matchesKey(name: string, patterns: ReadonlyArray<RegExp>): boolean {
  for (const re of patterns) if (re.test(name)) return true;
  return false;
}

function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let h = 0;
  for (const c of freq.values()) {
    const p = c / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

function isLikelySecretShape(s: string): boolean {
  // Heuristic: high entropy alone catches lots of normal strings (UUIDs,
  // public keys). We restrict the rule to strings dominated by base64/base32/hex
  // characters with no whitespace/punctuation runs.
  if (/\s/.test(s)) return false;
  // At least 80% of chars must be in the base64url/base62 alphabet.
  let n = 0;
  for (const ch of s) if (/[A-Za-z0-9_\-/+=]/.test(ch)) n++;
  return n / s.length >= 0.85;
}

function cap(v: unknown, r: Resolved): unknown {
  // Re-serialize; if it's larger than max_serialized_size_bytes, replace
  // with a marker. Avoids unbounded growth in audit / log pipelines.
  // Primitives (incl. undefined / null) are too small to need capping.
  if (
    v === undefined ||
    v === null ||
    typeof v === 'number' ||
    typeof v === 'boolean' ||
    typeof v === 'string'
  ) {
    return v;
  }
  let json: string;
  try {
    json = JSON.stringify(v);
  } catch {
    return '[UNSERIALIZABLE]';
  }
  if (typeof json !== 'string') return v;
  if (json.length <= r.max_serialized_size_bytes) return v;
  return {
    truncated: true,
    reason: 'max_serialized_size_kb',
    size_bytes: json.length,
    sample: json.slice(0, 256),
  };
}

/** Default singleton — used by metrics + logging modules. */
export const defaultScrubber = buildScrubber();
