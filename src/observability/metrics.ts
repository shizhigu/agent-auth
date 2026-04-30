/**
 * Prometheus-compatible metrics. SPEC §7.1.
 *
 * In-process registry that supports counters, gauges, and histograms.
 * Exposition format is Prometheus 0.0.4 (text/plain). The lib does NOT
 * start an HTTP server — the SaaS mounts an /metrics route and calls
 * `registry.exposition()` from there.
 *
 * Label cardinality: per RT-44 + §6.6, NO label may carry secrets,
 * key_ids, or subject_ids verbatim. Labels are passed through the
 * scrubber's key-name guard before they're stored.
 */

import { defaultScrubber } from './scrubber.js';

type Labels = Readonly<Record<string, string>>;

interface SeriesEntry {
  labels: Labels;
  /** counter: monotonic; gauge: current value; histogram: not used. */
  value: number;
  /** histogram-only: per-bucket cumulative counts + sum + count. */
  buckets?: Array<{ le: number; count: number }>;
  sum?: number;
  count?: number;
}

abstract class Metric {
  constructor(
    public readonly name: string,
    public readonly help: string,
    public readonly labelNames: ReadonlyArray<string>,
  ) {}

  abstract type(): 'counter' | 'gauge' | 'histogram';

  protected key(labels: Labels): string {
    const parts: string[] = [];
    for (const n of this.labelNames) parts.push(`${n}="${labels[n] ?? ''}"`);
    return parts.join(',');
  }
}

class Counter extends Metric {
  private series = new Map<string, SeriesEntry>();
  type() {
    return 'counter' as const;
  }
  inc(labels: Labels = {}, n = 1): void {
    const k = this.key(labels);
    const cur = this.series.get(k);
    if (cur) {
      cur.value += n;
    } else {
      this.series.set(k, { labels, value: n });
    }
  }
  snapshot(): ReadonlyArray<SeriesEntry> {
    return [...this.series.values()];
  }
}

class Gauge extends Metric {
  private series = new Map<string, SeriesEntry>();
  type() {
    return 'gauge' as const;
  }
  set(labels: Labels = {}, value: number): void {
    this.series.set(this.key(labels), { labels, value });
  }
  inc(labels: Labels = {}, n = 1): void {
    const k = this.key(labels);
    const cur = this.series.get(k);
    if (cur) cur.value += n;
    else this.series.set(k, { labels, value: n });
  }
  snapshot(): ReadonlyArray<SeriesEntry> {
    return [...this.series.values()];
  }
}

class Histogram extends Metric {
  private series = new Map<string, SeriesEntry>();
  constructor(
    name: string,
    help: string,
    labelNames: ReadonlyArray<string>,
    public readonly buckets: ReadonlyArray<number>,
  ) {
    super(name, help, labelNames);
  }
  type() {
    return 'histogram' as const;
  }
  observe(labels: Labels, value: number): void {
    const k = this.key(labels);
    let entry = this.series.get(k);
    if (!entry) {
      entry = {
        labels,
        value: 0,
        buckets: this.buckets.map((le) => ({ le, count: 0 })),
        sum: 0,
        count: 0,
      };
      this.series.set(k, entry);
    }
    entry.sum = (entry.sum ?? 0) + value;
    entry.count = (entry.count ?? 0) + 1;
    for (const b of entry.buckets!) {
      if (value <= b.le) b.count++;
    }
  }
  snapshot(): ReadonlyArray<SeriesEntry> {
    return [...this.series.values()];
  }
}

export class MetricsRegistry {
  private metrics = new Map<string, Counter | Gauge | Histogram>();
  constructor(public readonly prefix: string = 'agent_auth') {}

  counter(name: string, help: string, labelNames: ReadonlyArray<string> = []): Counter {
    const full = this.fullName(name);
    let m = this.metrics.get(full);
    if (!m) {
      m = new Counter(full, help, labelNames);
      this.metrics.set(full, m);
    }
    if (!(m instanceof Counter)) throw new Error(`metric_kind_mismatch: ${full}`);
    return m;
  }

  gauge(name: string, help: string, labelNames: ReadonlyArray<string> = []): Gauge {
    const full = this.fullName(name);
    let m = this.metrics.get(full);
    if (!m) {
      m = new Gauge(full, help, labelNames);
      this.metrics.set(full, m);
    }
    if (!(m instanceof Gauge)) throw new Error(`metric_kind_mismatch: ${full}`);
    return m;
  }

  histogram(
    name: string,
    help: string,
    labelNames: ReadonlyArray<string> = [],
    buckets: ReadonlyArray<number> = [0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1],
  ): Histogram {
    const full = this.fullName(name);
    let m = this.metrics.get(full);
    if (!m) {
      m = new Histogram(full, help, labelNames, buckets);
      this.metrics.set(full, m);
    }
    if (!(m instanceof Histogram)) throw new Error(`metric_kind_mismatch: ${full}`);
    return m;
  }

  /** Prometheus 0.0.4 text exposition. */
  exposition(): string {
    const out: string[] = [];
    for (const m of this.metrics.values()) {
      out.push(`# HELP ${m.name} ${m.help}`);
      out.push(`# TYPE ${m.name} ${m.type()}`);
      if (m instanceof Counter || m instanceof Gauge) {
        for (const s of m.snapshot()) {
          out.push(`${m.name}${formatLabels(s.labels)} ${s.value}`);
        }
      } else if (m instanceof Histogram) {
        for (const s of m.snapshot()) {
          for (const b of s.buckets!) {
            const labels = { ...s.labels, le: String(b.le) };
            out.push(`${m.name}_bucket${formatLabels(labels)} ${b.count}`);
          }
          out.push(`${m.name}_bucket${formatLabels({ ...s.labels, le: '+Inf' })} ${s.count ?? 0}`);
          out.push(`${m.name}_sum${formatLabels(s.labels)} ${s.sum ?? 0}`);
          out.push(`${m.name}_count${formatLabels(s.labels)} ${s.count ?? 0}`);
        }
      }
    }
    return out.join('\n') + '\n';
  }

  private fullName(name: string): string {
    return `${this.prefix}_${name}`;
  }
}

function formatLabels(labels: Labels): string {
  // Run label values through the scrubber to make sure no secret slips into
  // an exposition line (RT-44).
  const entries = Object.entries(labels);
  if (entries.length === 0) return '';
  const parts: string[] = [];
  for (const [k, raw] of entries) {
    const scrubbed = defaultScrubber.scrubLine(String(raw));
    parts.push(`${k}="${escapeLabelValue(scrubbed)}"`);
  }
  return `{${parts.join(',')}}`;
}

function escapeLabelValue(v: string): string {
  return v.replace(/\\/g, '\\\\').replace(/\n/g, '\\n').replace(/"/g, '\\"');
}
