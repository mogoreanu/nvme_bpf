// nvme_latency_web dashboard. Dependency free: plain DOM + canvas.
'use strict';

// ---------------------------------------------------------------------------
// Constants and state
// ---------------------------------------------------------------------------

const OPCODE_COLORS = {0: '#c77dff', 1: '#ffb020', 2: '#39ff7a'};
const OTHER_OPCODE_COLOR = '#38d6ff';
const CTRL_COLORS = ['#4f8dff', '#2ee6c8', '#ff7ad9', '#ffd84a', '#8f7dff'];
const PERCENTILES = [
  {key: 'p50', label: 'P50', color: '#4fd8ff'},
  {key: 'p90', label: 'P90', color: '#8dff5a'},
  {key: 'p99', label: 'P99', color: '#ffc02e'},
  {key: 'p999', label: 'P99.9', color: '#ff4f5e'},
];
const AVG_LINE = {key: 'avg', label: 'Avg', color: '#c8ccd4'};
const WINDOWS = [
  {s: 60, label: '1m'}, {s: 300, label: '5m'}, {s: 900, label: '15m'},
  {s: 3600, label: '1h'},
];
const MONO = '"JetBrains Mono", "SF Mono", Menlo, Consolas, "DejaVu Sans Mono", monospace';
const UI = 'system-ui, -apple-system, "Segoe UI", Roboto, Ubuntu, sans-serif';
const DRIVE_ICON =
    '<svg viewBox="0 0 24 24" class="%CLS%" aria-hidden="true">' +
    '<rect x="3" y="7" width="18" height="10" rx="2"/>' +
    '<path d="M6.5 12h6"/><circle cx="17" cy="12" r="1"/></svg>';

const store = {
  get(key, fallback) {
    try {
      const v = localStorage.getItem('nvme_latency_web.' + key);
      return v == null ? fallback : JSON.parse(v);
    } catch (e) {
      return fallback;
    }
  },
  set(key, value) {
    try {
      localStorage.setItem('nvme_latency_web.' + key, JSON.stringify(value));
    } catch (e) { /* Private mode. */ }
  },
};

const state = {
  config: null,
  data: null,
  windowS: store.get('windowS', 300),
  histMode: store.get('histMode', 'window'),
  ctrlPct: store.get('ctrlPct', 'p99'),  // Percentile compared on device pages.
  hidden: new Set(store.get('hidden', ['avg'])),
  paused: false,
  route: parseRoute(),
  hover: null,           // {kind: 'time', t} | {kind: 'hist', wrap, bucket}
  lastOk: 0,
  fetchError: null,
  structureKey: '',
  updaters: [],          // Functions refreshing text after new data.
};

const charts = new Set();  // Registered canvas charts, see registerChart().

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

const $ = (sel, root = document) => root.querySelector(sel);
const isNum = (v) => typeof v === 'number' && isFinite(v);
const clamp = (v, lo, hi) => Math.min(hi, Math.max(lo, v));

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text != null) e.textContent = text;
  return e;
}

function icon(cls) {
  const t = document.createElement('template');
  t.innerHTML = DRIVE_ICON.replace('%CLS%', cls);
  return t.content.firstChild;
}

function groupBy(items, keyFn) {
  const m = new Map();
  for (const it of items) {
    const k = keyFn(it);
    if (!m.has(k)) m.set(k, []);
    m.get(k).push(it);
  }
  return m;
}

function hexToRgb(hex) {
  const n = parseInt(hex.slice(1), 16);
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255];
}

function rgba(hex, a) {
  const [r, g, b] = hexToRgb(hex);
  return `rgba(${r},${g},${b},${a})`;
}

function lastValid(values) {
  for (let i = values.length - 1; i >= 0; i--) if (isNum(values[i])) return i;
  return -1;
}

// Routes: #/ (all devices), #/c/<ctrl_id> (one device), #/s/<series id>.
function parseRoute() {
  let m = /^#\/s\/([\w-]+)/.exec(location.hash);
  if (m) return {view: 'series', id: m[1]};
  m = /^#\/c\/(\d+)/.exec(location.hash);
  if (m) return {view: 'ctrl', ctrl: Number(m[1])};
  return {view: 'summary'};
}

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

function trimNum(x) {
  if (x >= 100) return String(Math.round(x));
  if (x >= 10) return String(+x.toFixed(1));
  return String(+x.toFixed(2));
}

function fmtUs(v) {
  if (!isNum(v)) return '—';
  if (v < 10) return v.toFixed(1) + ' µs';
  if (v < 1000) return Math.round(v) + ' µs';
  if (v < 1e6) return trimNum(v / 1e3) + ' ms';
  return trimNum(v / 1e6) + ' s';
}

function fmtUsAxis(v) {
  if (v < 1000) return trimNum(v) + 'µs';
  if (v < 1e6) return trimNum(v / 1e3) + 'ms';
  return trimNum(v / 1e6) + 's';
}

function fmtRate(v) {
  if (!isNum(v)) return '—';
  if (v < 10) return +v.toFixed(1) + '';
  if (v < 1000) return Math.round(v) + '';
  if (v < 1e6) return trimNum(v / 1e3) + 'k';
  return trimNum(v / 1e6) + 'M';
}

// Compact count for axes, at most one decimal: 7, 250, 2.7K, 3.4M.
function fmtCountAxis(v) {
  const units = [[1e9, 'G'], [1e6, 'M'], [1e3, 'K']];
  for (const [scale, unit] of units) {
    if (v >= scale) return +(v / scale).toFixed(1) + unit;
  }
  return String(Math.round(v));
}

function fmtCount(v) {
  if (!isNum(v)) return '—';
  if (v < 1e4) return Math.round(v).toLocaleString('en-US');
  if (v < 1e6) return trimNum(v / 1e3) + 'k';
  if (v < 1e9) return trimNum(v / 1e6) + 'M';
  return trimNum(v / 1e9) + 'G';
}

function pad2(n) { return String(n).padStart(2, '0'); }

function fmtClock(ms, seconds = true) {
  const d = new Date(ms);
  return pad2(d.getHours()) + ':' + pad2(d.getMinutes()) +
      (seconds ? ':' + pad2(d.getSeconds()) : '');
}

function fmtUptime(s) {
  s = Math.max(0, Math.floor(s));
  const h = Math.floor(s / 3600);
  return `${pad2(h)}:${pad2(Math.floor((s % 3600) / 60))}:${pad2(s % 60)}`;
}

function fmtDuration(s) {
  if (s < 60) return `${Math.round(s)} s`;
  if (s < 3600) return `${Math.round(s / 60)} min`;
  return `${trimNum(s / 3600)} h`;
}

function hex2(n) { return n.toString(16).padStart(2, '0'); }

// ---------------------------------------------------------------------------
// Series helpers
// ---------------------------------------------------------------------------

function allSeries() { return state.data ? state.data.series : []; }
function findSeries(id) { return allSeries().find((s) => s.id === id); }
function opColor(s) { return OPCODE_COLORS[s.opcode] || OTHER_OPCODE_COLOR; }
function seriesTitle(s) { return `nvme${s.ctrl_id} · ${s.opcode_name}`; }

function seriesSubtitle(s) {
  const parts = [];
  if (state.config && state.config.split_size) parts.push(s.size_class_name);
  parts.push(`opcode 0x${hex2(s.opcode)}`);
  return parts.join(' · ');
}

function latencyLines(id) {
  const s = findSeries(id);
  if (!s) return [];
  const lines = PERCENTILES.map((p) => ({
    key: p.key, label: p.label, color: p.color, values: s[p.key],
    hidden: state.hidden.has(p.key),
  }));
  lines.push({
    key: 'avg', label: AVG_LINE.label, color: AVG_LINE.color, values: s.avg,
    dash: [4, 4], width: 1.2, glow: false, hidden: state.hidden.has('avg'),
  });
  return lines;
}

function rateLines(id) {
  const s = findSeries(id);
  if (!s) return [];
  return [{key: 'iops', label: 'IOPS', color: opColor(s), values: s.iops, fill: true}];
}

function ctrlColor(ctrl) { return CTRL_COLORS[ctrl % CTRL_COLORS.length]; }
function ctrlSeries(ctrl) { return allSeries().filter((s) => s.ctrl_id === ctrl); }
function ctrlIds() { return [...new Set(allSeries().map((s) => s.ctrl_id))]; }

// Short name of a series within its controller, e.g. "Read" or "Read ≤ 16 KiB".
function opLabel(s) {
  return state.config.split_size && s.size_class_name !== 'all sizes' ?
      `${s.opcode_name} ${s.size_class_name}` : s.opcode_name;
}

// Line style per size class, so that size classes of the same opcode (same
// color) can be told apart.
const SIZE_DASH = [[], [7, 3], [2, 3]];
function opDash(s) {
  return state.config.split_size ? SIZE_DASH[s.size_class] || [] : [];
}

function sumOrNaN(values) {
  let sum = 0;
  let any = false;
  for (const v of values) if (isNum(v)) { sum += v; any = true; }
  return any ? sum : NaN;
}

// Aggregates of all the series of one controller.
function ctrlStats(ctrl) {
  const series = ctrlSeries(ctrl);
  const n = state.data ? state.data.t.length : 0;
  const iops = new Array(n);
  for (let i = 0; i < n; i++) {
    const v = sumOrNaN(series.map((s) => s.iops[i]));
    iops[i] = isNum(v) ? v : null;
  }
  const byOp = new Map();
  for (const s of series) {
    const v = isNum(s.recent.iops) ? s.recent.iops : 0;
    byOp.set(s.opcode_name, (byOp.get(s.opcode_name) || 0) + v);
  }
  let worst = null;
  for (const s of series) {
    if (isNum(s.recent.p99_us) && (!worst || s.recent.p99_us > worst.recent.p99_us)) worst = s;
  }
  return {
    series, iops, byOp, worst,
    total: sumOrNaN(series.map((s) => s.recent.iops)),
    peakIops: peak(iops),
    requests: series.reduce((acc, s) => acc + s.window.count, 0),
  };
}

// Peak of the sum of the IOPS of `items` over the window.
function peakTotalIops(items) {
  let peak = 0;
  const n = state.data ? state.data.t.length : 0;
  for (let i = 0; i < n; i++) {
    let sum = 0;
    for (const s of items) if (isNum(s.iops[i])) sum += s.iops[i];
    peak = Math.max(peak, sum);
  }
  return peak;
}

function peak(values) {
  let p = NaN;
  for (const v of values) if (isNum(v) && !(v <= p)) p = v;
  return p;
}

// ---------------------------------------------------------------------------
// Canvas charts
// ---------------------------------------------------------------------------

function prepCanvas(canvas) {
  const dpr = window.devicePixelRatio || 1;
  const w = Math.max(1, Math.round(canvas.clientWidth));
  const h = Math.max(1, Math.round(canvas.clientHeight));
  if (canvas.width !== Math.round(w * dpr) || canvas.height !== Math.round(h * dpr)) {
    canvas.width = Math.round(w * dpr);
    canvas.height = Math.round(h * dpr);
  }
  const ctx = canvas.getContext('2d');
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, w, h);
  return {ctx, w, h};
}

function makeChartWrap(cls) {
  const wrap = el('div', 'chart-wrap ' + cls);
  wrap.append(el('canvas', 'base'), el('canvas', 'overlay'));
  return wrap;
}

// A chart has a "base" canvas redrawn when data changes and an "overlay"
// canvas redrawn on hover, so moving the mouse stays cheap.
function registerChart(wrap, drawBase, drawOverlay) {
  const c = {
    wrap, base: wrap.querySelector('.base'), overlay: wrap.querySelector('.overlay'),
    drawBase, drawOverlay: drawOverlay || (() => {}), geom: null,
  };
  charts.add(c);
  return c;
}

function drawCharts() {
  for (const c of charts) {
    if (!c.wrap.isConnected) { charts.delete(c); continue; }
    c.drawBase(c);
    c.drawOverlay(c);
  }
}

let overlayFrame = 0;
function scheduleOverlays() {
  if (overlayFrame) return;
  overlayFrame = requestAnimationFrame(() => {
    overlayFrame = 0;
    for (const c of charts) c.drawOverlay(c);
  });
}

let chartsFrame = 0;
function scheduleCharts() {
  if (chartsFrame) return;
  chartsFrame = requestAnimationFrame(() => {
    chartsFrame = 0;
    drawCharts();
  });
}

function niceNum(x) {
  const e = Math.floor(Math.log10(x));
  const f = x / 10 ** e;
  const nf = f < 1.5 ? 1 : f < 2.25 ? 2 : f < 3.5 ? 2.5 : f < 7.5 ? 5 : 10;
  return nf * 10 ** e;
}

const TIME_STEPS = [1e3, 2e3, 5e3, 1e4, 15e3, 3e4, 6e4, 12e4, 3e5, 6e5, 9e5,
  18e5, 36e5, 72e5];
function niceTimeStep(ms) {
  return TIME_STEPS.find((s) => s >= ms) || TIME_STEPS[TIME_STEPS.length - 1];
}

// Linear scale from 0 with at most `maxTicks` labeled intervals.
function linearScale(hi, maxTicks) {
  if (!isNum(hi) || hi <= 0) hi = 1;
  const max = hi * 1.12;
  let step = niceNum(max / Math.max(1, maxTicks));
  while (Math.floor(max / step) > maxTicks) step = niceNum(step * 1.5);
  const ticks = [];
  for (let v = 0; v <= max; v += step) ticks.push(v);
  return {ticks, map: (v, top, h) => top + h - (v / max) * h};
}

function logScale(lo, hi) {
  if (!isNum(lo) || !isNum(hi) || lo <= 0) { lo = 20; hi = 2000; }
  const down = (v) => {
    const e = 10 ** Math.floor(Math.log10(v));
    return [5, 2, 1].map((m) => m * e).find((x) => x <= v * 1.0001) || e;
  };
  const up = (v) => {
    const e = 10 ** Math.floor(Math.log10(v));
    return [1, 2, 5, 10].map((m) => m * e).find((x) => x >= v * 0.9999);
  };
  let min = down(lo / 1.3);
  let max = up(hi * 1.3);
  while (max / min < 8) { min = down(min / 1.5); max = up(max * 1.5); }
  const l0 = Math.log10(min);
  const l1 = Math.log10(max);
  const mults = l1 - l0 > 2.3 ? [1] : [1, 2, 5];
  const ticks = [];
  for (let d = Math.floor(l0); d <= Math.ceil(l1); d++) {
    for (const m of mults) {
      const v = m * 10 ** d;
      if (v >= min * 0.999 && v <= max * 1.001) ticks.push(v);
    }
  }
  return {
    ticks,
    map: (v, top, h) => top + h - ((Math.log10(Math.max(v, 1e-3)) - l0) / (l1 - l0)) * h,
  };
}

function segments(values) {
  const segs = [];
  let cur = null;
  for (let i = 0; i < values.length; i++) {
    if (isNum(values[i])) {
      if (!cur) { cur = []; segs.push(cur); }
      cur.push(i);
    } else {
      cur = null;
    }
  }
  return segs;
}

// Draws a time series chart. `spec`:
//   lines():  [{key, label, color, values, dash, width, fill, glow, hidden}]
//   log:      log scale y axis.
//   fmt:      value formatter for tooltips, axisFmt: for axis labels.
//   accent:   grid/border color.
//   compact:  sparkline mode without axes.
//   markerKey: line whose latest value is marked on the right edge.
function drawTimeChart(c, spec) {
  const d = state.data;
  const {ctx, w, h} = prepCanvas(c.base);
  c.geom = null;
  const compact = !!spec.compact;
  const pad = compact ? {l: 0, r: 0, t: 2, b: 2} :
      {l: 52, r: 10, t: 8, b: spec.xLabels === false ? 4 : 20};
  const pw = w - pad.l - pad.r;
  const ph = h - pad.t - pad.b;
  if (!d || pw < 8 || ph < 8) return;

  const tMax = d.now_ms;
  const tMin = d.now_ms - d.window_ms;
  const xOf = (t) => pad.l + ((t - tMin) / (tMax - tMin)) * pw;
  const lines = spec.lines();
  let lo = Infinity;
  let hi = -Infinity;
  for (const L of lines) {
    if (L.hidden) continue;
    for (const v of L.values) {
      if (!isNum(v) || (spec.log && v <= 0)) continue;
      if (v < lo) lo = v;
      if (v > hi) hi = v;
    }
  }
  const scale = spec.log ? logScale(lo, hi) :
      linearScale(hi, clamp(Math.floor(ph / 18), 2, 5));
  const yOf = (v) => scale.map(v, pad.t, ph);
  const accent = spec.accent;

  // Background and grid. The vertical grid is aligned to wall clock time so
  // it scrolls with the data.
  ctx.fillStyle = rgba(accent, 0.05);
  ctx.fillRect(pad.l, pad.t, pw, ph);
  ctx.lineWidth = 1;
  ctx.strokeStyle = rgba(accent, 0.1);
  ctx.beginPath();
  const minor = niceTimeStep((tMax - tMin) / (compact ? 8 : 30));
  for (let t = Math.ceil(tMin / minor) * minor; t <= tMax; t += minor) {
    const x = Math.round(xOf(t)) + 0.5;
    ctx.moveTo(x, pad.t);
    ctx.lineTo(x, pad.t + ph);
  }
  if (compact) {
    for (let i = 1; i < 4; i++) {
      const y = Math.round(pad.t + (ph * i) / 4) + 0.5;
      ctx.moveTo(pad.l, y);
      ctx.lineTo(pad.l + pw, y);
    }
  }
  ctx.stroke();

  if (!compact) {
    ctx.strokeStyle = rgba(accent, 0.2);
    ctx.beginPath();
    for (const v of scale.ticks) {
      const y = Math.round(yOf(v)) + 0.5;
      if (y < pad.t || y > pad.t + ph) continue;
      ctx.moveTo(pad.l, y);
      ctx.lineTo(pad.l + pw, y);
    }
    ctx.stroke();

    ctx.fillStyle = '#8b9099';
    ctx.font = '10px ' + MONO;
    ctx.textAlign = 'right';
    ctx.textBaseline = 'middle';
    for (const v of scale.ticks) {
      const y = yOf(v);
      if (y < pad.t - 1 || y > pad.t + ph + 1) continue;
      ctx.fillText(spec.axisFmt(v), pad.l - 6, clamp(y, pad.t + 5, pad.t + ph - 4));
    }
    const major = niceTimeStep((tMax - tMin) / Math.max(2, Math.floor(pw / 95)));
    ctx.textAlign = 'center';
    ctx.textBaseline = 'top';
    for (let t = Math.ceil(tMin / major) * major; spec.xLabels !== false && t <= tMax; t += major) {
      const x = xOf(t);
      if (x < pad.l + 22 || x > pad.l + pw - 22) continue;
      ctx.fillText(fmtClock(t, major < 60000), x, pad.t + ph + 5);
    }
  }

  // Data. A point covers [t, t + step), draw it in the middle.
  const xs = d.t.map((t) => xOf(Math.min(t + d.step_ms / 2, tMax)));
  ctx.save();
  ctx.beginPath();
  ctx.rect(pad.l, pad.t, pw, ph);
  ctx.clip();
  for (const L of lines) {
    if (L.hidden) continue;
    const segs = segments(L.values);
    if (L.fill) {
      const g = ctx.createLinearGradient(0, pad.t, 0, pad.t + ph);
      g.addColorStop(0, rgba(L.color, 0.38));
      g.addColorStop(1, rgba(L.color, 0.03));
      ctx.fillStyle = g;
      for (const s of segs) {
        ctx.beginPath();
        ctx.moveTo(xs[s[0]], pad.t + ph);
        for (const i of s) ctx.lineTo(xs[i], yOf(L.values[i]));
        ctx.lineTo(xs[s[s.length - 1]], pad.t + ph);
        ctx.closePath();
        ctx.fill();
      }
    }
    ctx.strokeStyle = L.color;
    ctx.lineWidth = L.width || (compact ? 1.3 : 1.6);
    ctx.lineJoin = 'round';
    ctx.setLineDash(L.dash || []);
    ctx.shadowColor = L.color;
    ctx.shadowBlur = L.glow === false ? 0 : compact ? 4 : 7;
    ctx.beginPath();
    for (const s of segs) {
      const y0 = yOf(L.values[s[0]]);
      if (s.length === 1) {
        ctx.moveTo(xs[s[0]] - 1.5, y0);
        ctx.lineTo(xs[s[0]] + 1.5, y0);
        continue;
      }
      ctx.moveTo(xs[s[0]], y0);
      for (let k = 1; k < s.length; k++) ctx.lineTo(xs[s[k]], yOf(L.values[s[k]]));
    }
    ctx.stroke();
    ctx.shadowBlur = 0;
    ctx.setLineDash([]);
  }
  ctx.restore();

  ctx.strokeStyle = rgba(accent, 0.6);
  ctx.lineWidth = 1;
  ctx.strokeRect(pad.l + 0.5, pad.t + 0.5, pw - 1, ph - 1);

  // Latest value marker, like a scrolling history pen.
  const marked = lines.find((L) => L.key === spec.markerKey && !L.hidden) ||
      lines.find((L) => !L.hidden);
  if (marked) {
    const i = lastValid(marked.values);
    if (i >= 0) {
      const y = clamp(yOf(marked.values[i]), pad.t + 4, pad.t + ph - 4);
      const x = pad.l + pw - 1;
      ctx.fillStyle = '#ffffff';
      ctx.beginPath();
      ctx.moveTo(x, y - 4.5);
      ctx.lineTo(x - 6, y);
      ctx.lineTo(x, y + 4.5);
      ctx.closePath();
      ctx.fill();
    }
  }
  c.geom = {pad, pw, ph, tMin, tMax, xs, yOf, lines, fmt: spec.fmt};
}

function nearestIndex(t) {
  const d = state.data;
  if (!d || !d.t.length) return -1;
  return clamp(Math.round((t - d.step_ms / 2 - d.t[0]) / d.step_ms), 0, d.t.length - 1);
}

function drawTimeOverlay(c) {
  const {ctx} = prepCanvas(c.overlay);
  const g = c.geom;
  if (!g || !state.hover || state.hover.kind !== 'time') return;
  const i = nearestIndex(state.hover.t);
  if (i < 0) return;
  const x = Math.round(g.xs[i]) + 0.5;
  ctx.strokeStyle = 'rgba(255,255,255,0.4)';
  ctx.lineWidth = 1;
  ctx.beginPath();
  ctx.moveTo(x, g.pad.t);
  ctx.lineTo(x, g.pad.t + g.ph);
  ctx.stroke();
  for (const L of g.lines) {
    if (L.hidden || !isNum(L.values[i])) continue;
    const y = g.yOf(L.values[i]);
    if (y < g.pad.t || y > g.pad.t + g.ph) continue;
    ctx.fillStyle = L.color;
    ctx.strokeStyle = '#111';
    ctx.beginPath();
    ctx.arc(x, y, 3.2, 0, 2 * Math.PI);
    ctx.fill();
    ctx.stroke();
  }
}

function attachTimeHover(c) {
  c.wrap.addEventListener('mousemove', (ev) => {
    const g = c.geom;
    if (!g) return;
    const r = c.wrap.getBoundingClientRect();
    const x = ev.clientX - r.left;
    if (x < g.pad.l || x > g.pad.l + g.pw) { clearHover(); return; }
    state.hover = {kind: 'time', t: g.tMin + ((x - g.pad.l) / g.pw) * (g.tMax - g.tMin)};
    showTimeTooltip(c, ev);
    scheduleOverlays();
  });
  c.wrap.addEventListener('mouseleave', clearHover);
}

function clearHover() {
  if (!state.hover) return;
  state.hover = null;
  $('#tooltip').hidden = true;
  scheduleOverlays();
}

function placeTooltip(tip, ev) {
  tip.hidden = false;
  const r = tip.getBoundingClientRect();
  let x = ev.clientX + 16;
  let y = ev.clientY + 14;
  if (x + r.width > window.innerWidth - 8) x = ev.clientX - r.width - 16;
  if (y + r.height > window.innerHeight - 8) y = ev.clientY - r.height - 14;
  tip.style.left = x + 'px';
  tip.style.top = y + 'px';
}

function tooltipRow(color, label, value) {
  const row = el('div', 'tt-row');
  const dot = el('span', 'tt-dot');
  dot.style.background = color;
  row.append(dot, el('span', 'tt-label', label), el('span', 'tt-val', value));
  return row;
}

function showTimeTooltip(c, ev) {
  const d = state.data;
  const g = c.geom;
  const i = nearestIndex(state.hover.t);
  if (i < 0) return;
  const tip = $('#tooltip');
  tip.textContent = '';
  const t0 = d.t[i];
  tip.append(el('div', 'tt-time', d.step_ms > 1000 ?
      `${fmtClock(t0)} – ${fmtClock(t0 + d.step_ms)}` : fmtClock(t0)));
  for (const L of g.lines) {
    if (!L.hidden) tip.append(tooltipRow(L.color, L.label, g.fmt(L.values[i])));
  }
  placeTooltip(tip, ev);
}

// --- LED histogram ---------------------------------------------------------

function bucketOf(v, bounds) {
  for (let b = 0; b < bounds.length; b++) {
    const [lo, hi] = bounds[b];
    if (v >= lo && (hi == null || v < hi)) return b;
  }
  return bounds.length - 1;
}

// Draws a histogram as columns of LED segments. Column heights use a log
// scale so that the latency tail stays visible. `spec`:
//   counts(): counts per display bucket, color, markers(): [{label, value, color}]
function drawLedHistogram(c, spec) {
  const {ctx, w, h} = prepCanvas(c.base);
  c.geom = null;
  const counts = spec.counts();
  const bounds = state.config ? state.config.buckets : null;
  if (!counts || !bounds) return;
  const pad = {l: 50, r: 10, t: 28, b: 34};
  const pw = w - pad.l - pad.r;
  const ph = h - pad.t - pad.b;
  if (pw < 20 || ph < 20) return;
  const n = counts.length;
  let first = counts.findIndex((v) => v > 0);
  let last = n - 1;
  while (last >= 0 && !(counts[last] > 0)) last--;
  if (first < 0) {
    ctx.fillStyle = '#7d828b';
    ctx.font = '12px ' + UI;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText('No completions in this interval', w / 2, h / 2);
    return;
  }
  first = Math.max(0, first - 1);
  last = Math.min(n - 1, last + 1);
  while (last - first + 1 < 12 && (first > 0 || last < n - 1)) {
    if (last < n - 1) last++;
    if (last - first + 1 < 12 && first > 0) first--;
  }
  const nb = last - first + 1;
  const colW = pw / nb;
  const barW = Math.max(2, Math.min(colW - 3, colW * 0.78));
  const segH = 3;
  const gap = 2;
  const nSeg = Math.max(4, Math.floor((ph + gap) / (segH + gap)));
  const segY = (s) => pad.t + ph - (s + 1) * segH - s * gap;
  let max = 0;
  let total = 0;
  for (const v of counts) { max = Math.max(max, v); total += v; }
  const logMax = Math.log10(1 + max);

  // Log scale y axis: the columns are log10(1 + count) high. Ticks at powers of
  // ten and at the largest count.
  const stackH = nSeg * (segH + gap) - gap;
  const yOf = (v) => pad.t + ph - (Math.log10(1 + v) / logMax) * stackH;
  const ticks = [];
  for (let v = 1; v < max; v *= 10) ticks.push(v);
  while (ticks.length && yOf(ticks[ticks.length - 1]) - yOf(max) < 14) ticks.pop();
  ticks.push(max);
  ctx.font = '10px ' + MONO;
  ctx.textAlign = 'right';
  ctx.textBaseline = 'middle';
  for (const v of ticks) {
    const y = Math.round(yOf(v)) + 0.5;
    ctx.strokeStyle = 'rgba(255,255,255,0.07)';
    ctx.beginPath();
    ctx.moveTo(pad.l, y);
    ctx.lineTo(pad.l + pw, y);
    ctx.stroke();
    ctx.fillStyle = v === max ? '#c9ccd2' : '#8b9099';
    ctx.fillText(fmtCountAxis(v), pad.l - 8, y);
  }
  ctx.save();
  ctx.translate(11, pad.t + ph / 2);
  ctx.rotate(-Math.PI / 2);
  ctx.textAlign = 'center';
  ctx.fillStyle = '#6d717a';
  ctx.fillText('requests (log)', 0, 0);
  ctx.restore();

  for (let b = first; b <= last; b++) {
    const v = counts[b];
    const lit = v > 0 ? Math.max(1, Math.round((Math.log10(1 + v) / logMax) * nSeg)) : 0;
    const x = pad.l + (b - first) * colW + (colW - barW) / 2;
    ctx.fillStyle = rgba(spec.color, 0.09);
    for (let s = lit; s < nSeg; s++) ctx.fillRect(x, segY(s), barW, segH);
    if (lit) {
      ctx.save();
      ctx.shadowColor = spec.color;
      ctx.shadowBlur = 6;
      ctx.fillStyle = spec.color;
      for (let s = 0; s < lit; s++) ctx.fillRect(x, segY(s), barW, segH);
      ctx.restore();
    }
  }

  // Bucket boundaries.
  ctx.fillStyle = '#8b9099';
  ctx.font = '10px ' + MONO;
  ctx.textAlign = 'center';
  ctx.textBaseline = 'top';
  let labelRight = -Infinity;
  for (let b = first; b <= last + 1; b++) {
    const v = b <= last ? bounds[b][0] : bounds[last][1];
    if (!isNum(v)) continue;
    const x = pad.l + (b - first) * colW;
    ctx.fillRect(Math.round(x), pad.t + ph + 2, 1, 4);
    const label = fmtUsAxis(v);
    const half = ctx.measureText(label).width / 2;
    const lx = clamp(x, pad.l + half, pad.l + pw - half);
    if (lx - half < labelRight + 6) continue;
    ctx.fillText(label, lx, pad.t + ph + 8);
    labelRight = lx + half;
  }

  // Percentile markers.
  const markers = spec.markers().filter((m) => isNum(m.value))
      .sort((a, b) => a.value - b.value);
  let lastX = -1e9;
  let row = 0;
  for (const m of markers) {
    const b = bucketOf(m.value, bounds);
    if (b < first || b > last) continue;
    const [lo, hi] = bounds[b];
    const frac = isNum(hi) && hi > lo ? clamp((m.value - lo) / (hi - lo), 0, 1) : 0;
    const x = pad.l + (b - first + frac) * colW;
    row = x - lastX < 36 ? (row + 1) % 2 : 0;
    lastX = x;
    ctx.strokeStyle = m.color;
    ctx.setLineDash([3, 3]);
    ctx.beginPath();
    ctx.moveTo(Math.round(x) + 0.5, pad.t - 2 - row * 11);
    ctx.lineTo(Math.round(x) + 0.5, pad.t + ph);
    ctx.stroke();
    ctx.setLineDash([]);
    ctx.fillStyle = m.color;
    ctx.font = 'bold 10px ' + UI;
    ctx.textBaseline = 'bottom';
    ctx.fillText(m.label, clamp(x, pad.l + 14, pad.l + pw - 14), pad.t - 4 - row * 11);
  }
  c.geom = {pad, pw, ph, first, last, colW, counts, total, bounds};
}

function drawHistOverlay(c) {
  const {ctx} = prepCanvas(c.overlay);
  const g = c.geom;
  if (!g || !state.hover || state.hover.kind !== 'hist' || state.hover.wrap !== c.wrap) return;
  const b = state.hover.bucket;
  const x = g.pad.l + (b - g.first) * g.colW;
  ctx.strokeStyle = 'rgba(255,255,255,0.55)';
  ctx.lineWidth = 1;
  ctx.strokeRect(Math.round(x) + 0.5, g.pad.t - 0.5, Math.round(g.colW) - 1, g.ph + 1);
}

function attachHistHover(c, color) {
  c.wrap.addEventListener('mousemove', (ev) => {
    const g = c.geom;
    if (!g) return;
    const r = c.wrap.getBoundingClientRect();
    const b = g.first + Math.floor((ev.clientX - r.left - g.pad.l) / g.colW);
    if (b < g.first || b > g.last) { clearHover(); return; }
    state.hover = {kind: 'hist', wrap: c.wrap, bucket: b};
    let below = 0;
    for (let i = 0; i <= b; i++) below += g.counts[i];
    const [lo, hi] = g.bounds[b];
    const tip = $('#tooltip');
    tip.textContent = '';
    tip.append(el('div', 'tt-time', isNum(hi) ? `[${fmtUs(lo)}, ${fmtUs(hi)})` : `≥ ${fmtUs(lo)}`));
    const pct = (x) => (g.total ? ((100 * x) / g.total).toFixed(x === g.total ? 0 : 3) : '0') + '%';
    tip.append(tooltipRow(color, 'Requests', fmtCount(g.counts[b])));
    tip.append(tooltipRow(color, 'Share', pct(g.counts[b])));
    tip.append(tooltipRow('#9b9fa7', 'Cumulative', pct(below)));
    placeTooltip(tip, ev);
    scheduleOverlays();
  });
  c.wrap.addEventListener('mouseleave', clearHover);
}

// --- LED meter -------------------------------------------------------------

function rampColor(f) {
  if (f < 0.6) return '#39ff7a';
  if (f < 0.85) return '#ffc02e';
  return '#ff4f5e';
}

function drawLedMeter(c, frac, color, ramp) {
  const {ctx, w, h} = prepCanvas(c.base);
  const segW = 9;
  const gap = 3;
  const n = Math.max(4, Math.floor((w + gap) / (segW + gap)));
  const lit = isNum(frac) ? Math.round(clamp(frac, 0, 1) * n) : 0;
  for (let i = 0; i < n; i++) {
    const col = ramp ? rampColor(i / Math.max(1, n - 1)) : color;
    const x = i * (segW + gap);
    if (i < lit) {
      ctx.save();
      ctx.shadowColor = col;
      ctx.shadowBlur = 6;
      ctx.fillStyle = col;
      ctx.fillRect(x, 1, segW, h - 2);
      ctx.restore();
    } else {
      ctx.fillStyle = rgba(col, 0.13);
      ctx.fillRect(x, 1, segW, h - 2);
    }
  }
}

// ---------------------------------------------------------------------------
// Shared widgets
// ---------------------------------------------------------------------------

function makeLegend() {
  const legend = el('div', 'legend');
  for (const p of [...PERCENTILES, AVG_LINE]) {
    const chip = el('button', 'chip' + (state.hidden.has(p.key) ? ' off' : ''));
    chip.dataset.key = p.key;
    chip.style.setProperty('--c', p.color);
    chip.title = `Show / hide ${p.label}`;
    chip.append(el('span', 'chip-dot'), document.createTextNode(p.label));
    chip.addEventListener('click', (ev) => {
      ev.preventDefault();
      ev.stopPropagation();
      toggleLine(p.key);
    });
    legend.append(chip);
  }
  return legend;
}

function toggleLine(key) {
  if (state.hidden.has(key)) state.hidden.delete(key);
  else state.hidden.add(key);
  store.set('hidden', [...state.hidden]);
  for (const chip of document.querySelectorAll(`.chip[data-key="${key}"]`)) {
    chip.classList.toggle('off', state.hidden.has(key));
  }
  drawCharts();
}

function latencyChart(id, color, big) {
  const wrap = makeChartWrap('lat' + (big ? ' big' : ''));
  const c = registerChart(wrap, (c) => drawTimeChart(c, {
    lines: () => latencyLines(id), log: true, fmt: fmtUs, axisFmt: fmtUsAxis,
    accent: color, markerKey: 'p99',
  }), drawTimeOverlay);
  attachTimeHover(c);
  return wrap;
}

function rateChart(id, color, big) {
  const wrap = makeChartWrap('rate' + (big ? ' big' : ''));
  const c = registerChart(wrap, (c) => drawTimeChart(c, {
    lines: () => rateLines(id), log: false, fmt: (v) => fmtRate(v) + ' IOPS',
    axisFmt: fmtRate, accent: color, markerKey: 'iops', xLabels: !!big,
  }), drawTimeOverlay);
  attachTimeHover(c);
  return wrap;
}

function stat(label, valueFn) {
  const box = el('div', 'stat');
  const value = el('div', 'stat-value', '—');
  box.append(el('div', 'stat-label', label), value);
  state.updaters.push(() => { value.textContent = valueFn(); });
  return box;
}

// ---------------------------------------------------------------------------
// Views
// ---------------------------------------------------------------------------

function buildSidebar() {
  const list = $('#device-list');
  list.textContent = '';
  const route = state.route;
  $('#nav-summary').classList.toggle('active', route.view === 'summary');
  for (const ctrl of ctrlIds()) {
    // The device: links to its summary.
    const color = ctrlColor(ctrl);
    const dev = el('a', 'dev ctrl');
    dev.href = '#/c/' + ctrl;
    dev.title = `Summary of nvme${ctrl}`;
    dev.style.setProperty('--accent', color);
    if (route.view === 'ctrl' && route.ctrl === ctrl) dev.classList.add('active');
    const text = el('div', 'dev-text');
    const iops = el('div', 'dev-sub');
    const worst = el('div', 'dev-sub');
    text.append(el('div', 'dev-title', `nvme${ctrl}`), iops, worst);
    const thumb = makeChartWrap('thumb');
    registerChart(thumb, (c) => drawTimeChart(c, {
      lines: () => [{key: 'iops', label: 'IOPS', color, values: ctrlStats(ctrl).iops, fill: true}],
      log: false, compact: true, accent: color, markerKey: 'iops', fmt: fmtRate,
    }));
    dev.append(icon('dev-icon'), text, thumb);
    list.append(dev);
    state.updaters.push(() => {
      const st = ctrlStats(ctrl);
      iops.textContent = fmtRate(st.total) + ' IOPS';
      worst.textContent = st.worst ?
          `P99 ${fmtUs(st.worst.recent.p99_us)} ${st.worst.opcode_name}` : 'idle';
      worst.title = 'Worst P99 latency of the last few seconds';
    });

    // Its request types: link to their details.
    for (const s of ctrlSeries(ctrl)) {
      const opColorValue = opColor(s);
      const a = el('a', 'dev op');
      a.href = '#/s/' + s.id;
      a.title = seriesTitle(s);
      a.style.setProperty('--accent', opColorValue);
      if (route.view === 'series' && route.id === s.id) a.classList.add('active');
      const opText = el('div', 'dev-text');
      opText.append(el('div', 'dev-title', s.opcode_name));
      if (state.config.split_size) opText.append(el('div', 'dev-size', s.size_class_name));
      const p99 = el('div', 'dev-sub');
      const opIops = el('div', 'dev-sub');
      opText.append(p99, opIops);
      const opThumb = makeChartWrap('thumb');
      registerChart(opThumb, (c) => drawTimeChart(c, {
        lines: () => {
          const x = findSeries(s.id);
          return x ? [{key: 'p99', label: 'P99', color: opColorValue, values: x.p99}] : [];
        },
        log: true, compact: true, accent: opColorValue, markerKey: 'p99', fmt: fmtUs,
      }));
      a.append(el('span', 'op-tree'), opText, opThumb);
      list.append(a);
      state.updaters.push(() => {
        const x = findSeries(s.id);
        p99.textContent = 'P99 ' + fmtUs(x && x.recent.p99_us);
        opIops.textContent = fmtRate(x && x.recent.iops) + ' IOPS';
      });
    }
  }
}

function buildEmpty(content) {
  const box = el('div', 'empty');
  if (!state.data) {
    box.append(el('h2', null, 'Connecting…'));
    box.append(el('p', null, 'Waiting for the first data from nvme_latency_web.'));
  } else if (!state.data.status.healthy) {
    box.append(el('h2', null, 'Waiting for the collector'));
    box.append(el('p', null, state.data.status.last_error));
    box.append(el('p', null,
        'The dashboard runs unprivileged and reads the histograms exported by ' +
        'the nvme_latency collector, which loads the BPF program as root. ' +
        'Start it in another terminal:'));
    box.append(el('code', null, 'sudo nvme_latency --print=summary'));
  } else {
    box.append(el('h2', null, 'Waiting for NVMe completions'));
    box.append(el('p', null,
        (state.config.source === 'fake' ? 'The simulator is running' :
            'The BPF program is attached') +
        ', but no NVMe I/O completed yet' +
        (state.config.ctrl_id_filter >= 0 ? ` on nvme${state.config.ctrl_id_filter}` : '') +
        '. Generate some I/O, for example:'));
    box.append(el('code', null,
        'sudo fio --name=lat --filename=/dev/nvme0n1 --rw=randread --bs=4k \\\n' +
        '    --direct=1 --ioengine=io_uring --iodepth=1 --time_based --runtime=60 \\\n' +
        '    --readonly'));
  }
  content.append(box);
}

// A clickable tile with the totals of one controller.
function buildCtrlTile(ctrl) {
  const color = ctrlColor(ctrl);
  const tile = el('a', 'tile');
  tile.href = '#/c/' + ctrl;
  tile.title = `Open the summary of nvme${ctrl}`;
  tile.style.setProperty('--accent', color);
  const head = el('div', 'tile-head');
  const value = el('span', 'tile-value');
  head.append(icon('tile-icon'), el('span', 'tile-title', `nvme${ctrl}`), value);
  const sub = el('div', 'tile-sub');
  const meter = makeChartWrap('meter');
  tile.append(head, sub, meter);
  let st = null;
  state.updaters.push(() => {
    st = ctrlStats(ctrl);
    value.textContent = fmtRate(st.total) + ' IOPS';
    const mix = [...st.byOp].map(([op, v]) => `${op} ${fmtRate(v)}`).join(' · ');
    sub.textContent = mix + (st.worst ?
        `  ·  worst P99 ${fmtUs(st.worst.recent.p99_us)} (${st.worst.opcode_name})` : '');
  });
  registerChart(meter, (c) => drawLedMeter(
      c, st && st.peakIops > 0 ? st.total / st.peakIops : 0, color, false));
  return tile;
}

function buildSummary(content) {
  const root = el('div', 'summary');
  const tiles = el('div', 'tiles');
  for (const ctrl of ctrlIds()) tiles.append(buildCtrlTile(ctrl));
  const cards = el('div', 'cards');
  for (const s of allSeries()) cards.append(buildCard(s));
  root.append(tiles, cards);
  content.append(root);
}

function buildCard(s) {
  const color = opColor(s);
  const card = el('div', 'card');
  card.style.setProperty('--accent', color);

  const head = el('a', 'card-head');
  head.href = '#/s/' + s.id;
  const left = el('div');
  left.append(el('div', 'card-title', seriesTitle(s)), el('div', 'card-sub', seriesSubtitle(s)));
  const big = el('div', 'card-big');
  const bigValue = el('span', 'big-value');
  big.append(el('span', 'big-label', 'P99'), bigValue);
  head.append(left, big);

  const rateLabel = el('div', 'chart-label');
  const rateValue = el('span', 'val');
  rateLabel.append(el('span', null, 'Request rate'), rateValue);

  const stats = el('div', 'card-stats');
  const recent = (f) => () => { const x = findSeries(s.id); return x ? f(x.recent, x) : '—'; };
  stats.append(
      stat('P50', recent((r) => fmtUs(r.p50_us))),
      stat('P90', recent((r) => fmtUs(r.p90_us))),
      stat('P99.9', recent((r) => fmtUs(r.p999_us))),
      stat('Avg', recent((r) => fmtUs(r.avg_us))),
      stat('Requests', recent((r, x) => fmtCount(x.window.count))));

  card.append(head, makeLegend(), latencyChart(s.id, color, false), rateLabel,
      rateChart(s.id, color, false), stats);
  state.updaters.push(() => {
    const x = findSeries(s.id);
    bigValue.textContent = fmtUs(x && x.recent.p99_us);
    rateValue.textContent = fmtRate(x && x.recent.iops) + ' IOPS';
  });
  return card;
}

// Chips linking to the request types of a controller.
function opLegend(ctrl) {
  const legend = el('div', 'legend');
  for (const s of ctrlSeries(ctrl)) {
    const chip = el('a', 'chip');
    chip.href = '#/s/' + s.id;
    chip.title = `Open ${seriesTitle(s)}`;
    chip.style.setProperty('--c', opColor(s));
    chip.append(el('span', 'chip-dot'), document.createTextNode(opLabel(s)));
    legend.append(chip);
  }
  return legend;
}

// The summary of one controller: totals, its request types compared on shared
// graphs, a table and their cards.
function buildController(content, ctrl) {
  if (!ctrlSeries(ctrl).length) {
    const box = el('div', 'empty');
    box.append(el('h2', null, 'Unknown device'));
    const back = el('a', null, '← Back to the summary');
    back.href = '#/';
    box.append(el('p', null, `No data for nvme${ctrl}.`), back);
    content.append(box);
    return;
  }
  const color = ctrlColor(ctrl);
  const root = el('div', 'detail');
  root.style.setProperty('--accent', color);
  let st = ctrlStats(ctrl);
  state.updaters.push(() => { st = ctrlStats(ctrl); });

  // Header with the total request rate.
  const head = el('div', 'detail-head');
  const sub = el('div', 'detail-sub');
  const big = el('div', 'detail-big');
  const bigValue = el('span', 'big-value');
  big.append(el('span', 'big-label', 'IOPS · LAST FEW SECONDS'), bigValue);
  const meter = makeChartWrap('meter big');
  const meterBox = el('div', 'detail-meter');
  meterBox.title = 'Current request rate relative to the peak in the time window';
  meterBox.append(meter);
  head.append(el('div', 'detail-title', `nvme${ctrl}`), sub, big, meterBox);
  registerChart(meter, (c) => drawLedMeter(c, st.peakIops > 0 ? st.total / st.peakIops : 0, color, true));

  // Latency of the request types, one percentile at a time.
  const latLabel = el('div', 'section-label');
  const latTitle = el('span');
  const pctSeg = el('div', 'seg small');
  pctSeg.style.marginLeft = '12px';
  for (const p of PERCENTILES) {
    const b = el('button', state.ctrlPct === p.key ? 'active' : '', p.label);
    b.title = `Compare the ${p.label} latency of the request types`;
    b.addEventListener('click', () => {
      state.ctrlPct = p.key;
      store.set('ctrlPct', p.key);
      for (const x of pctSeg.children) x.classList.toggle('active', x === b);
      update();
    });
    pctSeg.append(b);
  }
  latLabel.append(latTitle, opLegend(ctrl), pctSeg);
  const lat = makeChartWrap('lat big');
  const lc = registerChart(lat, (c) => drawTimeChart(c, {
    lines: () => ctrlSeries(ctrl).map((s) => ({
      key: s.id, label: opLabel(s), color: opColor(s), dash: opDash(s),
      values: s[state.ctrlPct],
    })),
    log: true, fmt: fmtUs, axisFmt: fmtUsAxis, accent: color,
  }), drawTimeOverlay);
  attachTimeHover(lc);

  // Request rates, stacked up to the total.
  const rateLabel = el('div', 'section-label');
  const rateValue = el('span', 'section-value');
  rateLabel.append(el('span', null, 'Request rate by request type'), rateValue);
  const rate = makeChartWrap('rate big');
  const rc = registerChart(rate, (c) => drawTimeChart(c, {
    lines: () => {
      const ss = ctrlSeries(ctrl);
      const lines = ss.map((s) => ({
        key: s.id, label: opLabel(s), color: opColor(s), dash: opDash(s),
        values: s.iops, fill: ss.length === 1,
      }));
      if (ss.length > 1) {
        lines.unshift({key: 'total', label: 'Total', color: '#e8eaee', dash: [4, 4],
          width: 1.2, glow: false, values: st.iops});
      }
      return lines;
    },
    log: false, fmt: (v) => fmtRate(v) + ' IOPS', axisFmt: fmtRate, accent: color,
    markerKey: 'total',
  }), drawTimeOverlay);
  attachTimeHover(rc);

  // Table of the request types.
  const tablePanel = el('div', 'panel');
  const tableLabel = el('div', 'section-label');
  tableLabel.append(el('span', null, 'Request types · last few seconds'));
  const table = el('table', 'op-table');
  const headRow = el('tr');
  for (const h of ['Request type', 'IOPS', 'P50', 'P90', 'P99', 'P99.9', 'Average',
    'Requests in window']) {
    headRow.append(el('th', null, h));
  }
  table.append(el('thead'));
  table.firstChild.append(headRow);
  const tbody = el('tbody');
  for (const s of ctrlSeries(ctrl)) {
    const row = el('tr');
    const nameCell = el('td');
    const link = el('a', 'op-link');
    link.href = '#/s/' + s.id;
    link.style.setProperty('--c', opColor(s));
    link.append(el('span', 'chip-dot'), document.createTextNode(opLabel(s)));
    nameCell.append(link);
    row.append(nameCell);
    const cells = [];
    for (let i = 0; i < 7; i++) {
      const td = el('td', 'num', '—');
      cells.push(td);
      row.append(td);
    }
    tbody.append(row);
    state.updaters.push(() => {
      const x = findSeries(s.id);
      if (!x) return;
      const r = x.recent;
      const values = [fmtRate(r.iops), fmtUs(r.p50_us), fmtUs(r.p90_us), fmtUs(r.p99_us),
        fmtUs(r.p999_us), fmtUs(r.avg_us), fmtCount(x.window.count)];
      values.forEach((v, i) => { cells[i].textContent = v; });
    });
  }
  table.append(tbody);
  tablePanel.append(tableLabel, table);

  const cardsLabel = el('div', 'section-label');
  cardsLabel.append(el('span', null, 'Request type details'));
  const cards = el('div', 'cards');
  for (const s of ctrlSeries(ctrl)) cards.append(buildCard(s));

  root.append(head, latLabel, lat, rateLabel, rate, tablePanel, cardsLabel, cards);
  content.append(root);

  state.updaters.push(() => {
    const ops = [...st.byOp.keys()].join(', ');
    sub.textContent = `Controller ${ctrl} · ${ops} · ` +
        `${fmtCount(st.requests)} requests in the last ${fmtDuration(state.data.window_ms / 1000)}`;
    bigValue.textContent = fmtRate(st.total);
    const p = PERCENTILES.find((x) => x.key === state.ctrlPct);
    latTitle.textContent = `${p.label} latency by request type (log scale)`;
    rateValue.textContent = `${fmtRate(st.total)} IOPS now · peak ${fmtRate(st.peakIops)}`;
  });
}

function buildDetail(content, id) {
  const s = findSeries(id);
  if (!s) {
    const box = el('div', 'empty');
    box.append(el('h2', null, 'Unknown series'));
    const back = el('a', null, '← Back to the summary');
    back.href = '#/';
    box.append(el('p', null, `No data for "${id}".`), back);
    content.append(box);
    return;
  }
  const color = opColor(s);
  const root = el('div', 'detail');
  root.style.setProperty('--accent', color);

  const head = el('div', 'detail-head');
  const big = el('div', 'detail-big');
  const bigValue = el('span', 'big-value');
  big.append(el('span', 'big-label', 'P99 · LAST FEW SECONDS'), bigValue);
  const meter = makeChartWrap('meter big');
  const meterBox = el('div', 'detail-meter');
  meterBox.title = 'Current request rate relative to the peak in the time window';
  meterBox.append(meter);
  head.append(el('div', 'detail-title', seriesTitle(s)),
      el('div', 'detail-sub',
          `Controller ${s.ctrl_id} · ${s.opcode_name} (opcode 0x${hex2(s.opcode)}) · ` +
          s.size_class_name),
      big, meterBox);
  registerChart(meter, (c) => {
    const x = findSeries(id);
    const p = x ? peak(x.iops) : NaN;
    drawLedMeter(c, x && p > 0 ? x.recent.iops / p : 0, color, true);
  });

  const latLabel = el('div', 'section-label');
  latLabel.append(el('span', null, 'Latency percentiles (log scale)'), makeLegend());
  const rateLabel = el('div', 'section-label');
  const rateValue = el('span', null);
  rateLabel.append(el('span', null, 'Request rate'), rateValue);

  // Distribution panel.
  const histPanel = el('div', 'panel hist-panel');
  const histLabel = el('div', 'section-label');
  const histTitle = el('span');
  const modes = el('div', 'seg small');
  for (const [mode, label] of [['window', 'Time window'], ['lifetime', 'Since start']]) {
    const b = el('button', state.histMode === mode ? 'active' : '', label);
    b.addEventListener('click', () => {
      state.histMode = mode;
      store.set('histMode', mode);
      for (const x of modes.children) x.classList.toggle('active', x === b);
      update();
    });
    modes.append(b);
  }
  histLabel.append(histTitle, modes);
  const hist = makeChartWrap('hist');
  const hc = registerChart(hist, (c) => drawLedHistogram(c, {
    counts: () => {
      const x = findSeries(id);
      return x && (state.histMode === 'lifetime' ? x.lifetime_hist : x.window_hist);
    },
    color,
    markers: () => {
      const x = findSeries(id);
      if (!x) return [];
      const st = state.histMode === 'lifetime' ? x.lifetime : x.window;
      return PERCENTILES.map((p) => ({label: p.label, color: p.color, value: st[p.key + '_us']}));
    },
  }), drawHistOverlay);
  attachHistHover(hc, color);
  histPanel.append(histLabel, hist);

  // Statistics panel.
  const statsPanel = el('div', 'panel stats-groups');
  const get = (f) => () => { const x = findSeries(id); return x ? f(x) : '—'; };
  const group = (title, items) => {
    const g = el('div');
    const grid = el('div', 'stats-grid');
    grid.append(...items);
    g.append(el('div', 'stats-group-title', title), grid);
    return g;
  };
  statsPanel.append(
      group('Last few seconds', [
        stat('P50', get((x) => fmtUs(x.recent.p50_us))),
        stat('P90', get((x) => fmtUs(x.recent.p90_us))),
        stat('P99', get((x) => fmtUs(x.recent.p99_us))),
        stat('P99.9', get((x) => fmtUs(x.recent.p999_us))),
        stat('Average', get((x) => fmtUs(x.recent.avg_us))),
        stat('IOPS', get((x) => fmtRate(x.recent.iops))),
      ]),
      group('Time window', [
        stat('P99', get((x) => fmtUs(x.window.p99_us))),
        stat('P99.9', get((x) => fmtUs(x.window.p999_us))),
        stat('Average', get((x) => fmtUs(x.window.avg_us))),
        stat('Requests', get((x) => fmtCount(x.window.count))),
        stat('Avg IOPS', get((x) => fmtRate(x.window.iops))),
        stat('Peak IOPS', get((x) => fmtRate(peak(x.iops)))),
      ]),
      group('Since start', [
        stat('Requests', get((x) => fmtCount(x.lifetime.count))),
        stat('Average', get((x) => fmtUs(x.lifetime.avg_us))),
        stat('P99.9', get((x) => fmtUs(x.lifetime.p999_us))),
        stat('Above max bucket', get((x) => fmtCount(x.lifetime.overflow))),
        stat('Avg IOPS', get((x) => fmtRate(x.lifetime.iops))),
        stat('Duration', get((x) => fmtDuration(x.lifetime.duration_s))),
      ]));

  const bottom = el('div', 'detail-bottom');
  bottom.append(histPanel, statsPanel);
  root.append(head, latLabel, latencyChart(id, color, true), rateLabel,
      rateChart(id, color, true), bottom);
  content.append(root);

  state.updaters.push(() => {
    const x = findSeries(id);
    bigValue.textContent = fmtUs(x && x.recent.p99_us);
    rateValue.textContent = x ? `${fmtRate(x.recent.iops)} IOPS now · peak ${fmtRate(peak(x.iops))}` : '';
    histTitle.textContent = 'Latency distribution · ' + (state.histMode === 'lifetime' ?
        `${fmtCount(x && x.lifetime.count)} requests since start` :
        `${fmtCount(x && x.window.count)} requests in the last ${fmtDuration(state.data.window_ms / 1000)}`);
  });
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

function structureKey() {
  const ids = allSeries().map((s) => s.id).join(',');
  const empty = !state.data ? 'none' : ids ? '' : state.data.status.healthy ? 'idle' : 'down';
  const r = state.route;
  return `${r.view}|${r.id || ''}|${r.ctrl ?? ''}|${ids}|${empty}`;
}

// Sets the breadcrumbs of the top bar, e.g. Summary › nvme1 › Read.
function setTitle(parts) {
  const title = $('#page-title');
  title.textContent = '';
  parts.forEach((part, i) => {
    if (i) title.append(el('span', 'crumb-sep', '›'));
    const e = el(part.href ? 'a' : 'span', part.href ? 'crumb' : 'crumb current', part.label);
    if (part.href) e.href = part.href;
    title.append(e);
  });
  document.title = [...parts].reverse().map((p) => p.label).join(' · ') + ' · NVMe Latency' +
      (state.config ? ' · ' + state.config.hostname : '');
}

function rebuild() {
  charts.clear();
  state.updaters = [];
  clearHover();
  const content = $('#content');
  content.textContent = '';
  buildSidebar();
  const route = state.route;
  const home = {label: 'Summary', href: '#/'};
  if (!state.data || !allSeries().length) {
    setTitle([{label: 'Summary'}]);
    buildEmpty(content);
  } else if (route.view === 'series') {
    const s = findSeries(route.id);
    setTitle(s ? [home, {label: `nvme${s.ctrl_id}`, href: `#/c/${s.ctrl_id}`},
      {label: opLabel(s)}] : [home, {label: 'Unknown'}]);
    buildDetail(content, route.id);
  } else if (route.view === 'ctrl') {
    setTitle([home, {label: `nvme${route.ctrl}`}]);
    buildController(content, route.ctrl);
  } else {
    setTitle([{label: 'Summary'}]);
    buildSummary(content);
  }
}

function update() {
  const key = structureKey();
  if (key !== state.structureKey) {
    state.structureKey = key;
    rebuild();
  }
  for (const f of state.updaters) f();
  drawCharts();
  if (state.hover && state.hover.kind === 'time') scheduleOverlays();
  updateStatus();
}

function updateStatus() {
  const d = state.data;
  const cfg = state.config;
  const dot = $('#status-dot');
  const text = $('#status-text');
  const stale = Date.now() - state.lastOk > 5000;
  let cls = 'ok';
  let msg;
  if (state.fetchError && (stale || !d)) {
    cls = 'err';
    msg = `Cannot reach nvme_latency_web: ${state.fetchError}`;
  } else if (d && !d.status.healthy) {
    cls = 'warn';
    msg = d.status.last_error + (d.series.length ? ' · showing the last data received' : '');
  } else if (d) {
    const ctrls = new Set(d.series.map((s) => s.ctrl_id)).size;
    const src = cfg.source === 'fake' ? 'Simulated source' : 'Collector';
    msg = `${src} healthy · ${ctrls} controller${ctrls === 1 ? '' : 's'} · ` +
        `${d.series.length} series · ${cfg.sample_interval_ms / 1000} s sampling · ` +
        `${d.step_ms / 1000} s resolution · ${fmtCount(d.num_snapshots)} samples`;
  } else {
    cls = '';
    msg = 'Connecting…';
  }
  dot.className = 'dot ' + cls;
  text.textContent = msg;
  updateBadge();
  const live = $('#status-live');
  live.textContent = state.paused ? 'PAUSED' : 'LIVE';
  live.classList.toggle('paused', state.paused);
  if (cfg) $('#status-host').textContent = cfg.hostname;
}

function tickClock() {
  if (!state.config) return;
  const clock = $('#status-clock');
  clock.textContent = fmtUptime((Date.now() - state.config.start_ms) / 1000);
  clock.title = 'Collecting since ' + new Date(state.config.start_ms).toLocaleString();
}

// ---------------------------------------------------------------------------
// Data
// ---------------------------------------------------------------------------

async function fetchJson(url) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 5000);
  try {
    const r = await fetch(url, {cache: 'no-store', signal: ctrl.signal});
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    return await r.json();
  } finally {
    clearTimeout(timer);
  }
}

function maxPoints() {
  const width = Math.max(320, window.innerWidth - 330);
  return clamp(Math.round(width / 2), 120, 1200);
}

async function refresh() {
  try {
    const data = await fetchJson(
        `api/series?window_s=${state.windowS}&max_points=${maxPoints()}`);
    if (state.paused) return;
    if (state.config && data.config_id !== state.config.config_id) {
      state.config = await fetchJson('api/config');
      state.structureKey = '';
    }
    state.data = data;
    state.lastOk = Date.now();
    state.fetchError = null;
  } catch (e) {
    state.fetchError = e.name === 'AbortError' ? 'timeout' : e.message;
  }
  update();
}

let pollTimer = 0;
async function poll() {
  clearTimeout(pollTimer);
  if (!state.paused && !document.hidden) await refresh();
  const interval = clamp(state.config ? state.config.sample_interval_ms : 1000, 500, 5000);
  pollTimer = setTimeout(poll, interval);
}

async function loadConfig() {
  for (;;) {
    try {
      state.config = await fetchJson('api/config');
      return;
    } catch (e) {
      state.fetchError = e.message;
      updateStatus();
      await new Promise((r) => setTimeout(r, 2000));
    }
  }
}

// ---------------------------------------------------------------------------
// Controls and startup
// ---------------------------------------------------------------------------

function buildControls() {
  const seg = $('#window-seg');
  for (const w of WINDOWS) {
    if (state.config && w.s > state.config.history_s) continue;
    const b = el('button', w.s === state.windowS ? 'active' : '', w.label);
    b.title = `Show the last ${fmtDuration(w.s)}`;
    b.addEventListener('click', () => {
      state.windowS = w.s;
      store.set('windowS', w.s);
      for (const x of seg.children) x.classList.toggle('active', x === b);
      poll();
    });
    seg.append(b);
  }
  if (![...seg.children].some((b) => b.classList.contains('active')) && seg.lastChild) {
    seg.lastChild.click();
  }

  const pause = $('#pause-btn');
  const setPaused = (p) => {
    state.paused = p;
    pause.textContent = p ? 'Resume' : 'Pause';
    pause.classList.toggle('paused', p);
    updateStatus();
    if (!p) poll();
  };
  pause.addEventListener('click', () => setPaused(!state.paused));
  document.addEventListener('keydown', (ev) => {
    if (ev.key === ' ' && ev.target === document.body) {
      ev.preventDefault();
      setPaused(!state.paused);
    }
  });

  $('#sidebar-toggle').addEventListener('click', () => {
    $('#app').classList.toggle('no-sidebar');
    scheduleCharts();
  });

  updateBadge();
}

function updateBadge() {
  const badge = $('#source-badge');
  if (!state.config) return;
  badge.hidden = false;
  const healthy = state.data ? state.data.status.healthy : state.config.source !== 'none';
  if (!healthy) {
    badge.textContent = state.config.source === 'none' ? 'NO COLLECTOR' : 'COLLECTOR DOWN';
    badge.className = 'badge down';
    badge.title = 'Not receiving snapshots from: sudo nvme_latency';
  } else if (state.config.source === 'fake') {
    badge.textContent = 'SIMULATED DATA';
    badge.className = 'badge sim';
    badge.title = 'Started with --fake: the data is generated, not measured.';
  } else {
    badge.textContent = 'LIVE · BPF';
    badge.className = 'badge live';
    badge.title = 'Latency measured by the nvme_latency BPF program.';
  }
}

async function main() {
  window.addEventListener('hashchange', () => {
    state.route = parseRoute();
    update();
    $('#content').scrollTop = 0;
  });
  window.addEventListener('resize', scheduleCharts);
  document.addEventListener('visibilitychange', () => { if (!document.hidden) poll(); });
  updateStatus();
  await loadConfig();
  buildControls();
  update();
  tickClock();
  setInterval(tickClock, 1000);
  poll();
}

main();
