/**
 * CVE Analysis Tool (CAT) — app.js
 * Copyright (C) 2024-2026  Alexis Broniarczyk
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is provided in the hope that it will be useful, but 
 * it comes WITHOUT ANY WARRANTY, not even a guarantee that it works 
 * properly or is suitable for any specific use. For more information, 
 * see the GNU General Public License..
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/* =================================================================
   SOURCE CONFIG
   ================================================================= */
const SOURCE_CONFIG = [
  { name:"NVD",         url: cve=>`https://nvd.nist.gov/vuln/detail/${cve}` },
  { name:"RedHat",      url: cve=>`https://access.redhat.com/security/cve/${cve}` },
  { name:"SUSE",        url: cve=>`https://www.suse.com/security/cve/${cve}` },
  { name:"Debian",      url: cve=>`https://security-tracker.debian.org/tracker/${cve}` },
  { name:"Ubuntu",      url: cve=>`https://ubuntu.com/security/${cve}` },
  { name:"Microsoft",   url: cve=>`https://msrc.microsoft.com/update-guide/vulnerability/${cve}` },
  { name:"Amazon",      url: cve=>`https://explore.alas.aws.amazon.com/${cve}.html` },
  { name:"LibreOffice", url: cve=>`https://cs.libreoffice.org/about-us/security/advisories/${cve.toLowerCase()}/` },
  { name:"PostgreSQL",  url: cve=>`https://www.postgresql.org/support/security/${cve}/` },
  { name:"Oracle",      url: cve=>`https://www.oracle.com/security-alerts/alert-${cve.toLowerCase()}.html` },
  { name:"Xen",         url: _=>`https://xenbits.xen.org/xsa/xsa.json` },
  { name:"CISA",        url: cve=>`https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=${cve}` },
  { name:"ENISA",       url: cve=>`https://euvd.enisa.europa.eu/vulnerability/${cve}` },
];

// URL used as badge link in the description source column
const DESC_SOURCE_URLS = {
  CVEList:    cve=>{const[,y,n]=cve.split("-");return`https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/${y}/${Math.floor(parseInt(n,10)/1000)}xxx/${cve}.json`},
  NVD:        cve=>`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cve}`,
  RedHat:     cve=>{const y=cve.split("-")[1],id=cve.toLowerCase().replace(/^cve-/,"");return`https://security.access.redhat.com/data/csaf/v2/vex/${y}/cve-${id}.json`},
  SUSE:       cve=>`https://ftp.suse.com/pub/projects/security/csaf-vex/${cve.toLowerCase()}.json`,
  Debian:     cve=>`https://security-tracker.debian.org/tracker/${cve}`,
  Ubuntu:     cve=>`https://ubuntu.com/security/cves/${cve}.json`,
  Microsoft:  cve=>{const y=cve.split("-")[1];return`https://msrc.microsoft.com/csaf/vex/${y}/msrc_${cve.toLowerCase()}.json`},
  Amazon:     cve=>`https://explore.alas.aws.amazon.com/${cve}.html`,
  LibreOffice:cve=>`https://cs.libreoffice.org/about-us/security/advisories/${cve.toLowerCase()}/`,
  PostgreSQL: cve=>`https://www.postgresql.org/support/security/${cve}/`,
  Oracle:     cve=>`https://www.oracle.com/security-alerts/alert-${cve.toLowerCase()}.html`,
  Xen:        _=>`https://xenbits.xen.org/xsa/xsa.json`,
  CISA:       _=>`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`,
  ENISA:      cve=>`https://euvdservices.enisa.europa.eu/api/enisaid?id=${encodeURIComponent(cve)}`,
};

const PROXY    = "__WORKER_PROXY__";
const DELAY_MS = 400;

/* =================================================================
   PROXY
   ================================================================= */
const MAX_CONCURRENT = 8;
let   _activeReqs    = 0;
const _reqQueue      = [];

function _acquireSlot() {
  if (_activeReqs < MAX_CONCURRENT) { _activeReqs++; return Promise.resolve(); }
  return new Promise(resolve => _reqQueue.push(resolve));
}
function _releaseSlot() {
  if (_reqQueue.length > 0) { _reqQueue.shift()(); }   // next slot
  else                      { _activeReqs--; }
}

async function proxyFetch(url, type="json") {
  for (let attempt = 0; attempt < 3; attempt++) {
    if (attempt > 0) await wait(1500 * attempt);
    await _acquireSlot();
    let released = false;
    try {
      const r = await fetch(PROXY + encodeURIComponent(url));
      if (r.status === 429) { _releaseSlot(); released = true; continue; }
      if (!r.ok) return null;
      const d = type === "json" ? await r.json() : await r.text();
      return d;
    } catch { return null; }
    finally { if (!released) _releaseSlot(); }
  }
  return null;
}

async function proxyFetchWithStatus(url, type="json") {
  for (let attempt = 0; attempt < 3; attempt++) {
    if (attempt > 0) await wait(1500 * attempt);
    await _acquireSlot();
    let released = false;
    try {
      const r = await fetch(PROXY + encodeURIComponent(url));
      if (r.status === 429) { _releaseSlot(); released = true; continue; }
      if (!r.ok) return { data: null, httpStatus: r.status };
      const d = type === "json" ? await r.json() : await r.text();
      return { data: d, httpStatus: r.status };
    } catch { return { data: null, httpStatus: 0 }; }
    finally { if (!released) _releaseSlot(); }
  }
  return { data: null, httpStatus: 429 };
}
async function checkUrl(url) {
  const r = await proxyFetchWithStatus(url, "text");
  if (r.httpStatus === 0) return "networkerror";
  if (!r.data || r.httpStatus === 404) return "fail";
  return "ok";
}

/* =================================================================
   THEME
   ================================================================= */
function toggleTheme() {
  const next = document.documentElement.getAttribute("data-theme") === "dark" ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", next);
  localStorage.setItem("theme", next);
}

/* =================================================================
   TEXT UTILITIES
   ================================================================= */
function extractCveIds(s) { return [...new Set((s.match(/CVE-\d{4}-\d{4,7}/gi) || []).map(c => c.toUpperCase()))]; }

/* Build a shareable URL containing the given CVE IDs as a query string */
function buildPermalink(cves) {
  const base = location.origin + location.pathname.replace(/index\.html$/i, '');
  return `${base}?cves=${[...cves].join(",")}`;
}
function esc(s) { return String(s ?? "").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;"); }
function normalizeText(s) {
  if (!s) return null;
  let t = String(s).replace(/<[^>]*>/g," ").replace(/[\x00-\x09\x0B-\x1F\x7F]/g," ").replace(/\s+/g," ").trim();
  while (t.startsWith("[") && t.endsWith("]")) t = t.slice(1,-1).trim();
  return t || null;
}
function normalizeForComparison(s) {
  if (!s) return "";
  return String(s).replace(/<[^>]*>/g," ")
    .replace(/[\u2018\u2019\u201A\u201B\u2032\u2035\u02BC]/g,"'")
    .replace(/[\u201C\u201D\u201E\u201F\u2033\u2036]/g,'"')
    .replace(/[\u2010\u2011\u2012\u2013\u2014\u2015\u2212]/g,"-")
    .replace(/\u2026/g,"...").replace(/[\u00A0\u202F\u2009\u200B\u3000]/g," ")
    .replace(/[\x00-\x09\x0B-\x1F\x7F]/g," ").replace(/\s+/g," ").trim().toLowerCase();
}
function sameDescription(a, b) { return !!a && !!b && normalizeForComparison(a) === normalizeForComparison(b); }
function cvssColorClass(s) { if (s == null || s === 0) return "bg-none"; if (s < 4) return "bg-low"; if (s < 7) return "bg-medium"; if (s < 9) return "bg-high"; return "bg-critical"; }
const wait = ms => new Promise(r => setTimeout(r, ms));

/* =================================================================
   CVE PERSISTENCE
   ─────────────────────────────────────────────────────────────────
   Master list : localStorage "cat_cves"     — max 25 IDs (oldest→newest)
   Data cache  : localStorage "cat_cve_{ID}" — TTL 7 days
   Landing     : sessionStorage "cat_curtain" — TTL 1 hour
   ================================================================= */
const MAX_CVES       = 25;
const LS_TTL_MS      = 7 * 24 * 60 * 60 * 1000; // 7 days
const CURTAIN_KEY    = "cat_curtain";
const CURTAIN_TTL_MS = 60 * 60 * 1000;           // 1 hour

/* ── Master list helpers ── */
function storageGetCves() {
  try { return JSON.parse(localStorage.getItem("cat_cves") || "[]"); } catch { return []; }
}
function storageSetCves(l) { localStorage.setItem("cat_cves", JSON.stringify(l)); }

/* ── Add a CVE to the master list ── */
function storageAddCve(cve) {
  const l = storageGetCves();
  if (l.includes(cve)) return;
  l.push(cve);
  if (l.length > MAX_CVES) { _dataDel(l.shift()); }   // evict oldest
  storageSetCves(l);
}

function storageRemoveCve(cve) {
  storageSetCves(storageGetCves().filter(c => c !== cve));
  _dataDel(cve);
}

function storageClearCves() {
  localStorage.removeItem("cat_cves");
  _dataDelAll();
}

/* ── Data helpers ── */
function _dataDel(cve) { localStorage.removeItem(`cat_cve_${cve}`); }

function _dataDelAll() {
  const prefix = "cat_cve_";
  Object.keys(localStorage).filter(k => k.startsWith(prefix)).forEach(k => localStorage.removeItem(k));
}

/* ── LRU-aware write to localStorage (safety net for quota) ── */
function _writeWithLRU(key, serialised) {
  for (let attempt = 0; attempt < 30; attempt++) {
    try { localStorage.setItem(key, serialised); return; }
    catch (e) {
      if (e.name !== "QuotaExceededError" && e.name !== "NS_ERROR_DOM_QUOTA_REACHED") return;
      let oldestKey = null, oldestTs = Infinity;
      for (let i = 0; i < localStorage.length; i++) {
        const k = localStorage.key(i);
        if (!k || !k.startsWith("cat_cve_") || k === key) continue;
        try { const ts = JSON.parse(localStorage.getItem(k))?.ts ?? 0; if (ts < oldestTs) { oldestTs = ts; oldestKey = k; } }
        catch { oldestKey = k; oldestTs = 0; }
      }
      if (!oldestKey) return;
      localStorage.removeItem(oldestKey);
    }
  }
}

/* ── Save after Phase-2 settles ── */
function sessionSave(cve, ctx, cvssBase) {
  if (!storageGetCves().includes(cve)) return;         // CVE not in master list → skip
  const { statuses, urls } = _getDotStatuses(cve);
  const payload = {
    ts: Date.now(), ttl: LS_TTL_MS,
    ctx: {
      cveListData:     ctx.cveListData     ?? null,
      nvdData:         ctx.nvdData         ?? null,
      nvdNetworkError: ctx.nvdResult?.networkError || false,
      rhOld:           ctx.rhOld           ?? null,
      rhCsaf:          ctx.rhCsaf          ?? null,
      suseCsaf:        ctx.suseCsaf        ?? null,
      debianData:      ctx.debianData      ?? null,
      ubuntuData:      ctx.ubuntuData
        ? { ...ctx.ubuntuData, rawData: ctx.ubuntuData.rawData
            ? { references: ctx.ubuntuData.rawData.references || [] }
            : null }
        : null,
      msrcData:        ctx.msrcData        ?? null,
      amazonData:      ctx.amazonData      ?? null,
      libreofficeData: ctx.libreofficeData ?? null,
      postgresData:    ctx.postgresData    ?? null,
      oracleData:      ctx.oracleData      ?? null,
      xenData:         ctx.xenData         ?? null,
      cisaData:        ctx.cisaData        ?? null,
      enisaData:       ctx.enisaData       ?? null,
      epssData:        ctx.epssData        ?? null,
    },
    cvssBase,
    dotStatuses: statuses,
    dotUrls:     urls,
  };
  _writeWithLRU(`cat_cve_${cve}`, JSON.stringify(payload));
}

/* ── Load from localStorage ── */
function sessionLoad(cve) {
  const key = `cat_cve_${cve}`;
  try {
    const raw = localStorage.getItem(key);
    if (!raw) return null;
    const p = JSON.parse(raw);
    const ttl = p.ttl ?? LS_TTL_MS;
    if (Date.now() - p.ts > ttl) { localStorage.removeItem(key); return null; }    return p;
  } catch { return null; }
}

/* ── Remove / clear ── */
function sessionRemove(cve) { _dataDel(cve); }
function sessionClearAll()  { _dataDelAll(); }

/* ── Landing curtain cache (sessionStorage, TTL 1 hour) ── */
function _curtainSave(payload) {
  try { sessionStorage.setItem(CURTAIN_KEY, JSON.stringify({ ts: Date.now(), ...payload })); }
  catch { /* quota exceeded — skip */ }
}
function _curtainLoad() {
  try {
    const raw = sessionStorage.getItem(CURTAIN_KEY);
    if (!raw) return null;
    const p = JSON.parse(raw);
    if (Date.now() - p.ts > CURTAIN_TTL_MS) { sessionStorage.removeItem(CURTAIN_KEY); return null; }
    return p;
  } catch { return null; }
}

function _getDotStatuses(cve) {
  const statuses = {}, urls = {};
  SOURCE_CONFIG.forEach(src => {
    const chip = document.getElementById(`dot-${src.name}-${cve}`);
    const dot  = chip?.querySelector(".dot");
    const cls  = dot ? Array.from(dot.classList).find(c => c.startsWith("dot-") && c !== "dot") : null;
    statuses[src.name] = cls ? cls.replace("dot-", "") : "wait";
    urls[src.name]     = chip?.href || "";
  });
  return { statuses, urls };
}

/* =================================================================
   CVSS UTILITIES
   ================================================================= */

/** Retourne tous les containers ADP du CVEList JSON (tableau, peut être vide) */
function getAdpContainers(cveListData) {
  const adp = cveListData?.containers?.adp;
  if (!adp) return [];
  return Array.isArray(adp) ? adp : [adp];
}

/** Extrait les métriques CVSS d'un container (cna ou adp) dans une liste */
function extractMetricsFromContainer(container, source, list) {
  (container?.metrics || []).forEach(m => {
    if (m.cvssV2)   pushCvss(list, "v2.0", m.cvssV2,   source);
    if (m.cvssV3)   pushCvss(list, "v3.0", m.cvssV3,   source);
    if (m.cvssV3_1) pushCvss(list, "v3.1", m.cvssV3_1, source);
    if (m.cvssV4)   pushCvss(list, "v4.0", m.cvssV4,   source);
    // Format 5.1 : cvssV4_0 peut aussi apparaître
    if (m.cvssV4_0) pushCvss(list, "v4.0", m.cvssV4_0, source);
    // Format score objet avec version et data imbriqués
    for (const [k, v] of Object.entries(m)) {
      if (!v || typeof v !== "object" || v.baseScore == null) continue;
      if (["cvssV2","cvssV3","cvssV3_1","cvssV4","cvssV4_0"].includes(k)) continue;
      const ver = detectCvssVersion(v.vectorString);
      if (ver) pushCvss(list, ver, v, source);
    }
  });
}


function detectCvssVersion(v) {
  if (!v) return null;
  const m = String(v).match(/^CVSS:(\d+\.\d+)\//i); if (m) return `v${m[1]}`;
  if (/^AV:[NALP]\/AC:[LMH]\/A[Uu]:[NSM]/i.test(v)) return "v2.0";
  return null;
}
function normalizeVector(version, raw) {
  if (!raw) return "";
  const v = String(raw).replace(/^CVSS:[^/]+\//i, "");
  const l = {"v4.0":11,"v3.1":8,"v3.0":8,"v2.0":6}[version];
  return l ? v.split("/").slice(0, l).join("/") : v;
}
function pushCvss(list, version, data, source) {
  if (data?.baseScore == null) return;
  const score = parseFloat(data.baseScore); if (isNaN(score)) return;
  const vector = normalizeVector(version, data.vectorString); if (!vector) return;
  const ex = list.find(c => c.version === version && c.score === score && c.vector === vector);
  if (ex) { if (!ex.sources.includes(source)) ex.sources.push(source); }
  else list.push({ version, score, vector, sources: [source] });
}
function sortCvss(list) {
  const w = {"v4.0":4,"v3.1":3.1,"v3.0":3,"v2.0":2};
  return list.sort((a,b) => b.score !== a.score ? b.score - a.score : (w[b.version]||0) - (w[a.version]||0));
}

/* =================================================================
   CWE UTILITIES
   ================================================================= */
function pushCwe(list, id, name, source) {
  if (!id) return;
  const c = String(id).trim().toUpperCase(); if (!/^CWE-\d+$/.test(c)) return;
  const ex = list.find(x => x.id === c);
  if (ex) { if (name && !ex.name) ex.name = normalizeText(name); if (!ex.sources.includes(source)) ex.sources.push(source); }
  else list.push({ id: c, name: normalizeText(name) || null, sources: [source] });
}
/* =================================================================
   CWE LOCAL DATABASE — injected by <script src="data/cwe.js">
   That script sets window._CWE_DB = { "ID": {n,d,c}, ... }
   No fetch needed — works on file://, http:// and https://.
   Falls back to cwe.mitre.org scraping if the script is absent.
   ================================================================= */
function getCweDb() {
  return window._CWE_DB || null;
}

async function fetchCweName(cweId) {
  const num = cweId.replace(/^CWE-/i, "");
  const db  = await getCweDb();
  if (db?.[num]?.n) return db[num].n;
  // Fallback: scrape mitre.org if local DB unavailable
  const html = await proxyFetch(`https://cwe.mitre.org/data/definitions/${num}.html`, "text");
  if (!html) return null;
  const m = html.match(/<title[^>]*>CWE\s*-\s*CWE-\d+:\s*([^<(]+)/i); if (m) return m[1].trim();
  const h = html.match(/<h2[^>]*>CWE-\d+:\s*([^<]+)/i); return h ? h[1].trim() : null;
}
function collectCweList(cveListData, nvdData, rhCsaf, suseCsaf, msrcVuln, cisaData) {
  const list = [], cna = cveListData?.containers?.cna;

  /** Extract CWE from cna or adp */
  function extractCwesFromContainer(container, source) {
    (container?.problemTypes || []).forEach(pt => (pt.descriptions || []).forEach(d => {
      // Case 1: explicit cweId field (clean, authoritative)
      if (d.cweId) {
        let cweName = null;
        if (d.description) {
          const m = String(d.description).match(/^CWE-\d+\s+([^\n]+)/i);
          if (m) cweName = m[1].trim();
          else if (!/^CWE-\d+$/i.test(d.description.trim())) cweName = d.description;
        }
        pushCwe(list, d.cweId, cweName, source);
        return;
      }
      // Case 2: no cweId field — scan description for ALL CWE-NNNN patterns
      if (!d.description) return;
      const desc = String(d.description);
      // Build a name map from "CWE-NNN Some Name" patterns (one per line or segment)
      const nameMap = {};
      for (const seg of desc.split(/[\n,;]+/)) {
        const m = seg.trim().match(/^(CWE-\d+)\s+(.+)/i);
        if (m) nameMap[m[1].toUpperCase()] = m[2].trim();
      }
      const allIds = [...desc.matchAll(/\b(CWE-\d+)\b/gi)];
      if (allIds.length > 0) {
        allIds.forEach(m => pushCwe(list, m[1].toUpperCase(), nameMap[m[1].toUpperCase()] ?? null, source));
      } else if (d.type === "CWE") {
        pushCwe(list, null, desc, source);
      }
    }));
  }
  const cnaSource = normalizeText(cveListData?.containers?.cna?.providerMetadata?.shortName) || "CVEList";
  extractCwesFromContainer(cna, cnaSource);
  // ADP containers
  getAdpContainers(cveListData).forEach(adp => extractCwesFromContainer(adp, "CISA-ADP"));

  (nvdData?.weaknesses || []).forEach(w => (w.description || []).forEach(d => pushCwe(list, d.value, null, "NVD")));
  function fromCsaf(csaf, src) {
    const v = csaf?.document?.vulnerabilities?.[0] || csaf?.vulnerabilities?.[0]; if (!v) return;
    if (v.cwe?.id) pushCwe(list, v.cwe.id, v.cwe.name, src);
    (v.cwes || []).forEach(c => pushCwe(list, c.id, c.name, src));
  }
  fromCsaf(rhCsaf, "RedHat"); fromCsaf(suseCsaf, "SUSE");
  if (msrcVuln?.cwe?.id) pushCwe(list, msrcVuln.cwe.id, msrcVuln.cwe.name, "Microsoft");
  if (cisaData?.cwes) {
    (Array.isArray(cisaData.cwes) ? cisaData.cwes : [cisaData.cwes])
      .forEach(c => { if (c) pushCwe(list, String(c).trim(), null, "CISA"); });
  }
  list.sort((a,b) => parseInt(a.id.slice(4)) - parseInt(b.id.slice(4)));
  return list;
}

/* =================================================================
   REFERENCE UTILITIES
   ================================================================= */
const REF_IGNORE = /\/(csaf|vex|csaf-vex)\//i;
const SOURCE_DOMAINS = {
  RedHat:    url => /access\.redhat\.com/i.test(url),
  SUSE:      url => /suse\.com|novell\.com|opensuse\.org/i.test(url),
  Ubuntu:    url => /ubuntu\.com/i.test(url),
  Microsoft: url => /microsoft\.com/i.test(url),
  Debian:    url => /debian\.org/i.test(url),
};
function getExcludedRefUrls(cve) {
  const s = new Set();
  for (const src of SOURCE_CONFIG) s.add(src.url(cve));
  for (const fn of Object.values(DESC_SOURCE_URLS)) s.add(fn(cve));
  s.add(`https://nvd.nist.gov/vuln/detail/${cve.toUpperCase()}`);
  s.add(`https://nvd.nist.gov/vuln/detail/${cve.toLowerCase()}`);
  s.add(`https://www.cve.org/CVERecord?id=${cve.toUpperCase()}`);
  s.add(`https://www.cve.org/CVERecord?id=${cve.toLowerCase()}`);
  return s;
}
function pushRef(list, url, source) {
  if (!url || typeof url !== "string") return;
  const u = url.trim(); if (!u.startsWith("http")) return; if (REF_IGNORE.test(u)) return;
  const ex = list.find(r => r.url === u);
  if (ex) { if (!ex.sources.includes(source)) ex.sources.push(source); }
  else list.push({ url: u, sources: [source] });
}
function collectRefs(cvl, nvd, rhC, suC, msV, ubRaw, cisaData, debianRefs, enisaRefs, notAffectedSources = new Set(), excludedUrls = new Set()) {
  const list = [], cna = cvl?.containers?.cna;
  const rhV = rhC?.document?.vulnerabilities?.[0] || rhC?.vulnerabilities?.[0];
  const suV = suC?.document?.vulnerabilities?.[0] || suC?.vulnerabilities?.[0];
  (cna?.references || []).forEach(r => pushRef(list, r.url, "CVEList"));
  // ADP containers references
  getAdpContainers(cvl).forEach(adp => (adp.references || []).forEach(r => pushRef(list, r.url, "CVEList")));
  (nvd?.references || []).forEach(r => pushRef(list, r.url, "NVD"));
  (rhV?.references || []).forEach(r => pushRef(list, r.url, "RedHat"));
  (suV?.references || []).forEach(r => pushRef(list, r.url, "SUSE"));
  (msV?.references || []).forEach(r => pushRef(list, r.url, "Microsoft"));
  (ubRaw?.references || []).forEach(r => { const u = typeof r === "string" ? r : r?.url; pushRef(list, u, "Ubuntu"); });
  (debianRefs || []).forEach(u => pushRef(list, u, "Debian"));
  (enisaRefs || []).forEach(u => pushRef(list, u, "ENISA"));
  if (cisaData?.notes) {
    const notes = cisaData.notes;
    (Array.isArray(notes) ? notes : [notes]).forEach(n => {
      const u = typeof n === "string" ? n : (n?.url || n?.value || null);
      if (u) pushRef(list, u, "CISA");
    });
  }
  return list.filter(ref => {
    if (excludedUrls.has(ref.url)) return false;
    for (const [src, fn] of Object.entries(SOURCE_DOMAINS)) {
      if (notAffectedSources.has(src) && fn(ref.url)) return false;
    }
    return true;
  });
}
function computeNotAffected(ctx) {
  const s = new Set();
  if (ctx.rhOld !== undefined && ctx.rhCsaf !== undefined) {
    const rhDesc = extractDescFromCsaf(ctx.rhCsaf) || extractDescFromRedHatLegacy(ctx.rhOld);
    if (!rhDesc && !ctx.rhOld?.cvss3?.cvss3_base_score && !ctx.rhOld?.cvss?.cvss_base_score) s.add("RedHat");
  }
  if (ctx.suseCsaf !== undefined && !extractDescFromCsaf(ctx.suseCsaf) && !ctx.suseCsaf) s.add("SUSE");
  if (ctx.ubuntuData !== undefined && ctx.ubuntuData?.notAffected) s.add("Ubuntu");
  if (ctx.msrcData !== undefined && ctx.msrcData?.dotStatus !== "ok") s.add("Microsoft");
  if (ctx.debianData !== undefined && ctx.debianData?.notAffected) s.add("Debian");
  return s;
}

/* =================================================================
   DATA FETCHERS
   ================================================================= */
async function fetchCveListData(cve) {
  const [,y,n] = cve.split("-");
  return proxyFetch(`https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/${y}/${Math.floor(parseInt(n,10)/1000)}xxx/${cve}.json`, "json");
}

async function fetchNvdData(cve) {
  const r = await proxyFetchWithStatus(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cve}`, "json");
  if (r.httpStatus === 0) return { data: null, networkError: true };
  const data = (r.data?.totalResults > 0) ? (r.data?.vulnerabilities?.[0]?.cve || null) : null;
  return { data, networkError: false };
}
async function fetchRedHatData(cve) { return proxyFetch(`https://access.redhat.com/hydra/rest/securitydata/cve/${cve}.json`, "json"); }
async function fetchRedHatCsaf(cve) {
  const y = cve.split("-")[1], id = cve.toLowerCase().replace(/^cve-/, "");
  return proxyFetch(`https://security.access.redhat.com/data/csaf/v2/vex/${y}/cve-${id}.json`, "json");
}
async function fetchSuseCsaf(cve) {
  const r = await proxyFetchWithStatus(`https://ftp.suse.com/pub/projects/security/csaf-vex/${cve.toLowerCase()}.json`, "json");
  if (r.httpStatus === 0) return { data: null, networkError: true };
  return { data: r.httpStatus === 200 ? r.data : null, networkError: false };
}
async function fetchDebianDescription(cve) {
  const r = await proxyFetchWithStatus(`https://security-tracker.debian.org/tracker/${encodeURIComponent(cve)}`, "text");
  if (r.httpStatus === 0) return { desc: null, refs: [], notAffected: null, networkError: true };
  const html = r.data;
  if (!html || r.httpStatus === 404) return { desc: null, refs: [], notAffected: null, networkError: false };
  const notForUs = /NOT-FOR-US/i.test(html) || /RESERVED/i.test(html) && !/\bpackage\b/i.test(html);
  const hasAffected = /(vulnerable|open|unfixed)/i.test(html);
  const notAffected = notForUs || !hasAffected;
  const doc = new DOMParser().parseFromString(html, "text/html");
  let desc = null;
  const tds = Array.from(doc.querySelectorAll("td"));
  for (let i = 0; i < tds.length - 1; i++) {
    if (tds[i].textContent.trim().replace(/:$/, "").toLowerCase() === "description") {
      desc = normalizeText(tds[i+1].textContent) || null; break;
    }
  }
  // Refs: only from <pre> siblings that follow <h2>Notes</h2> (or <h3>)
  const refs = [];
  for (const h of doc.querySelectorAll("h2, h3")) {
    if (/^notes?$/i.test(h.textContent.trim())) {
      let sib = h.nextElementSibling;
      while (sib && !/^H[123]$/.test(sib.tagName)) {
        if (sib.tagName === "PRE") {
          sib.querySelectorAll("a[href]").forEach(a => {
            const u = a.getAttribute("href");
            if (u && u.startsWith("http")) refs.push(u);
          });
        }
        sib = sib.nextElementSibling;
      }
      break;
    }
  }
  return { desc, refs, notAffected, networkError: false };
}
async function fetchUbuntuData(cve) {
  let data = await proxyFetch(`https://ubuntu.com/security/cves/${cve}.json`, "json");
  if (!data) data = await proxyFetch(`https://ubuntu.com/security/api/v1/cves/${cve}`, "json");
  if (!data) return { desc: null, ubuntuDesc: null, notAffected: null, networkError: true, cvssList: [], rawData: null };
  const desc = normalizeText(data.description) || null;
  const ubuntuDesc = normalizeText(data.ubuntu_description) || null;
  const noteNotAffected = /does not apply to software found in ubuntu/i.test(data.note || "");
  const INACTIVE = new Set(["not-affected","DNE","dne","ignored"]);
  const packages = Array.isArray(data.packages) ? data.packages : [];
  const hasActive = packages.some(pkg => (Array.isArray(pkg.statuses) ? pkg.statuses : []).some(s => !INACTIVE.has(s.status)));
  const notAffected = noteNotAffected || packages.length === 0 || !hasActive;
  const cvssList = [];
  function pushU(sv, vv) {
    if (sv == null || !vv) return;
    const score = parseFloat(sv); if (isNaN(score)) return;
    const version = detectCvssVersion(String(vv)); if (!version) return;
    pushCvss(cvssList, version, { baseScore: score, vectorString: String(vv) }, "Ubuntu");
  }
  const bm3 = data.impact?.baseMetricV3?.cvssV3, bm2 = data.impact?.baseMetricV2?.cvssV2;
  pushU(bm3?.baseScore, bm3?.vectorString); pushU(bm2?.baseScore, bm2?.vectorString);
  pushU(data.cvss3?.nvd_score, data.cvss3?.nvd_vector); pushU(data.cvss3?.ubuntu_score, data.cvss3?.ubuntu_vector);
  pushU(data.cvss?.nvd_score, data.cvss?.nvd_vector); pushU(data.cvss?.ubuntu_score, data.cvss?.ubuntu_vector);
  pushU(data.cvss_score, data.cvss_vector); pushU(data.cvss?.base_score, data.cvss?.vector_string);
  pushU(data.cvss3?.base_score, data.cvss3?.vector_string); pushU(data.base_score, data.vector_string);
  pushU(data.score, data.vector); pushU(data.cvss?.baseScore, data.cvss?.vectorString);
  for (const entry of (data.scores || data.metrics || [])) {
    if (entry?.baseScore != null && entry?.vectorString) pushU(entry.baseScore, entry.vectorString);
    for (const [, obj] of Object.entries(entry || {})) if (obj && typeof obj === "object" && obj.baseScore != null) pushU(obj.baseScore, obj.vectorString);
  }
  return { desc, ubuntuDesc, notAffected, networkError: false, cvssList, rawData: data };
}
function parseMsrcCsaf(csafData) {
  const vuln = csafData?.vulnerabilities?.[0];
  if (!vuln) return null;
  let desc = null;
  for (const ref of (Array.isArray(vuln.references) ? vuln.references : [])) {
    const raw = normalizeText(ref.summary);
    if (!raw || /^CVE-\d{4}-\d+$/i.test(raw.trim())) continue;
    const clean = raw.replace(/^CVE-\d{4}-\d+\s+/i, "").replace(/\s*-\s*VEX\s*$/i, "").trim();
    if (clean) { desc = clean; break; }
  }
  if (!desc) {
    const notes = Array.isArray(vuln.notes) ? vuln.notes : [];
    const note = notes.find(n => n.category === "description") || notes.find(n => n.category === "general");
    if (note) desc = normalizeText(Array.isArray(note.text) ? note.text.join(" ") : note.text) || null;
  }
  const cvssList = [];
  for (const score of (vuln.scores || [])) {
    for (const [, obj] of Object.entries(score)) {
      if (!obj || typeof obj !== "object" || obj.baseScore == null) continue;
      const version = detectCvssVersion(obj.vectorString);
      if (version) pushCvss(cvssList, version, { baseScore: obj.baseScore, vectorString: obj.vectorString }, "Microsoft");
    }
  }
  return (desc || cvssList.length || vuln) ? { desc, cvssList, vuln } : null;
}
function parseMsrcApi(apiData, cve) {
  const items = apiData?.value;
  if (!Array.isArray(items) || !items.length) return null;
  const entry = items.find(i => (i.cveNumber || "").toUpperCase() === cve.toUpperCase()) || items[0];
  if (!entry) return null;
  const desc = normalizeText(entry.cveTitle) || null;
  const cvssList = [];
  if (entry.baseScore != null && entry.vectorString) {
    const version = detectCvssVersion(entry.vectorString) || "v3.1";
    pushCvss(cvssList, version, { baseScore: entry.baseScore, vectorString: entry.vectorString }, "Microsoft");
  }
  return { desc, cvssList, found: true };
}
function parseMsrcCircl(circlData, cve) {
  if (!circlData) return null;
  let items = [];
  if (Array.isArray(circlData)) items = circlData;
  else if (Array.isArray(circlData.results)) items = circlData.results;
  else if (circlData.id || circlData.summary) items = [circlData];
  else { for (const v of Object.values(circlData)) { if (Array.isArray(v)) { items = v; break; } } }
  if (!items.length) return null;
  const entry = items.find(i => (i.id || i.cveId || i["CVE-ID"] || "").toUpperCase() === cve.toUpperCase()) || items[0];
  if (!entry) return null;
  const desc = normalizeText(entry.summary || entry.description) || null;
  const cvssList = [];
  const v3 = entry.cvss3?.cvssV3 || entry.cvssV3 || entry.impact?.baseMetricV3?.cvssV3;
  if (v3?.baseScore) {
    const ver = detectCvssVersion(v3.vectorString) || "v3.1";
    pushCvss(cvssList, ver, { baseScore: v3.baseScore, vectorString: v3.vectorString }, "Microsoft");
  }
  if (!cvssList.length && entry.cvss != null && entry["cvss-vector"]) {
    const ver = detectCvssVersion(entry["cvss-vector"]) || "v2.0";
    pushCvss(cvssList, ver, { baseScore: parseFloat(entry.cvss), vectorString: entry["cvss-vector"] }, "Microsoft");
  }
  return (desc || cvssList.length) ? { desc, cvssList } : null;
}
async function fetchMsrcData(cve) {
  const year      = cve.split("-")[1];
  const csafUrl   = `https://msrc.microsoft.com/csaf/vex/${year}/msrc_${cve.toLowerCase()}.json`;
  const pageUrl   = `https://msrc.microsoft.com/update-guide/vulnerability/${cve}`;
  const sugUrl    = `https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability?%24filter=cveNumber+eq+%27${cve}%27`;
  const circlUrl  = `https://cve.circl.lu/search?q=msrc_${cve.toLowerCase()}`;
  const [sugRes, csafRes, circlRes] = await Promise.all([
    proxyFetchWithStatus(sugUrl, "json"),
    proxyFetchWithStatus(csafUrl, "json"),
    proxyFetchWithStatus(circlUrl, "json"),
  ]);
  const fromCsaf  = parseMsrcCsaf(csafRes.data);
  const fromSug   = parseMsrcApi(sugRes.data, cve);
  const fromCircl = parseMsrcCircl(circlRes.data, cve);
  const sugOk   = sugRes.httpStatus   === 200 && fromSug   !== null;
  const csafOk  = csafRes.httpStatus  === 200 && fromCsaf  !== null;
  const circlOk = circlRes.httpStatus === 200 && fromCircl !== null;
  const allNetErr = sugRes.httpStatus === 0 && csafRes.httpStatus === 0 && circlRes.httpStatus === 0;
  let dotStatus;
  if (allNetErr) dotStatus = "networkerror";
  else if (sugOk || csafOk || circlOk) dotStatus = "ok";
  else if (sugRes.httpStatus === 0 && csafRes.httpStatus === 0) dotStatus = "networkerror";
  else dotStatus = "fail";
  const desc = fromCsaf?.desc || fromSug?.desc || fromCircl?.desc || null;
  const cvssList = fromCsaf?.cvssList?.length ? fromCsaf.cvssList : fromSug?.cvssList?.length ? fromSug.cvssList : fromCircl?.cvssList?.length ? fromCircl.cvssList : [];
  const vuln = fromCsaf?.vuln || null;
  const descSourceUrl = fromCsaf?.desc ? csafUrl : fromSug?.desc ? pageUrl : fromCircl?.desc ? circlUrl : csafUrl;
  return { dotStatus, dotUrl: pageUrl, desc, cvssList, vuln, descSourceUrl };
}
async function fetchAmazonData(cve) {
  const result = await proxyFetchWithStatus(`https://explore.alas.aws.amazon.com/${cve}.html`, "text");
  if (result.httpStatus === 0) return { desc: null, cvssList: [], networkError: true, pageFound: false };
  if (!result.data || result.httpStatus === 404) return { desc: null, cvssList: [], networkError: false, pageFound: false };
  const doc = new DOMParser().parseFromString(result.data, "text/html");
  let desc = null;
  const descEl = doc.querySelector("#description-content,.description-content");
  if (descEl) {
    const clone = descEl.cloneNode(true);
    clone.querySelectorAll("br").forEach(br => { br.replaceWith(doc.createTextNode("¶¶")); });
    const paras = clone.textContent.split("¶¶").map(s => s.replace(/\s+/g," ").trim()).filter(Boolean);
    desc = paras.length ? paras.join(" ") : null;
    if (!desc) desc = normalizeText(descEl.textContent) || null;
  }
  if (!desc) {
    const allHeadings = Array.from(doc.querySelectorAll("h1,h2,h3,h4,h5,dt,p>strong,p>b,th"));
    const descHeading = allHeadings.find(el => el.textContent.trim().toLowerCase() === "description");
    if (descHeading) {
      const paras = [];
      let sib = descHeading.parentElement?.nextElementSibling || descHeading.nextElementSibling;
      while (sib) {
        const tag = sib.tagName.toUpperCase();
        if (/^H[1-4]$/.test(tag)) break;
        if (tag === "P") { const t = normalizeText(sib.textContent); if (t) paras.push(t); }
        else if (tag === "DIV" || tag === "SECTION") {
          const clone = sib.cloneNode(true);
          clone.querySelectorAll("br").forEach(br => { br.replaceWith(document.createTextNode("¶¶")); });
          clone.textContent.split("¶¶").map(s => s.replace(/\s+/g," ").trim()).filter(Boolean).forEach(t => paras.push(t));
          break;
        }
        sib = sib.nextElementSibling;
      }
      if (paras.length) desc = paras.join("\n\n");
    }
  }
  if (desc) desc = desc.replace(/^description\s*:\s*/i, "").trim() || null;
  const cvssList = [];
  const cvssHeadings = Array.from(doc.querySelectorAll("h1,h2,h3,h4"));
  const cvssH = cvssHeadings.find(h => /cvss\s*(scores?|v\d)/i.test(h.textContent));
  let cvssTable = null;
  if (cvssH) { let el = cvssH.nextElementSibling; while (el) { if (el.tagName === "TABLE") { cvssTable = el; break; } el = el.nextElementSibling; } }
  if (!cvssTable) cvssTable = doc.querySelector("table");
  if (cvssTable) {
    const rows = Array.from(cvssTable.querySelectorAll("tr"));
    for (const row of rows) {
      const cells = Array.from(row.querySelectorAll("td,th"));
      if (cells.length < 3) continue;
      if (!/amazon\s*linux/i.test(cells[0].textContent.trim())) continue;
      const scoreText = (cells[2].querySelector("a")?.textContent || cells[2].textContent).trim();
      const score = parseFloat(scoreText);
      if (isNaN(score) || score <= 0 || score > 10) continue;
      let vector = null;
      if (cells[3]) {
        const link = cells[3].querySelector("a");
        const linkText = (link?.textContent || "").trim();
        if (/^CVSS:/i.test(linkText) || /^AV:/i.test(linkText)) vector = linkText;
        else if (link?.href) { const m = decodeURIComponent(link.href).match(/vector=([^&]+)/); if (m) vector = m[1]; }
        if (!vector) { const ct = cells[3].textContent.trim(); if (/^CVSS:/i.test(ct) || /^AV:/i.test(ct)) vector = ct; }
      }
      if (vector) { const version = detectCvssVersion(vector); if (version) pushCvss(cvssList, version, { baseScore: score, vectorString: vector }, "Amazon"); }
      break;
    }
  }
  return { desc, cvssList, networkError: false, pageFound: true };
}
// After:
async function fetchLibreOfficeData(cve) {
  const cveLow = cve.toLowerCase();
  const primaryUrl  = `https://www.libreoffice.org/about-us/security/advisories/${cveLow}/`;
  const fallbackUrl = `https://cs.libreoffice.org/about-us/security/advisories/${cveLow}/`;
  let result = await proxyFetchWithStatus(primaryUrl, "text");
  // Detect redirect to generic security index (no CVE-specific content returned)
  if (result.httpStatus === 200 && result.data &&
      !result.data.includes(cveLow) && !result.data.includes(cve.toUpperCase())) {
    result = await proxyFetchWithStatus(fallbackUrl, "text");
  }
  const url = fallbackUrl; // chip/badge always points to the reliable cs. mirror
  if (result.httpStatus === 0) return { desc: null, networkError: true, pageFound: false };
  if (!result.data || result.httpStatus === 404) return { desc: null, networkError: false, pageFound: false };
  const doc = new DOMParser().parseFromString(result.data, "text/html");
  let desc = null;
  const walker = document.createTreeWalker(doc.body, NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT);
  let collecting = false, parts = [], node = walker.nextNode();
  while (node) {
    if (node.nodeType === Node.ELEMENT_NODE) {
      const tag = node.tagName.toUpperCase();
      if ((tag === "STRONG" || tag === "B") && node.textContent.trim().toLowerCase() === "description") { collecting = true; node = walker.nextNode(); continue; }
      if (collecting && (tag === "STRONG" || tag === "B") && node.textContent.trim().toLowerCase() === "credits") break;
    } else if (collecting && node.nodeType === Node.TEXT_NODE) {
      const t = (node.nodeValue || "").replace(/\s+/g," ").trim(); if (t) parts.push(t);
    }
    node = walker.nextNode();
  }
  if (parts.length) desc = parts.join(" ").replace(/\s{2,}/g," ").trim() || null;
  if (desc) desc = desc.replace(/^description\s*:\s*/i, "").replace(/^\s*:\s*/, "").trim() || null;
  return { desc, networkError: false, pageFound: !!desc };
}
async function fetchPostgreSQLData(cve) {
  const url = `https://www.postgresql.org/support/security/${cve}/`;
  const result = await proxyFetchWithStatus(url, "text");
  if (result.httpStatus === 0) return { desc: null, cvssList: [], networkError: true, pageFound: false };
  if (!result.data || result.httpStatus === 404) return { desc: null, cvssList: [], networkError: false, pageFound: false };
  const doc = new DOMParser().parseFromString(result.data, "text/html");
  let desc = null;
  const ps = Array.from(doc.querySelectorAll("main p,.content p,article p,p"));
  for (const p of ps) { const t = normalizeText(p.textContent); if (t && t.length > 60 && t.includes(" ")) { desc = t; break; } }
  const cvssList = [];
  const headings = Array.from(doc.querySelectorAll("h1,h2,h3,h4"));
  const cvssH = headings.find(h => /CVSS\s*[34]/i.test(h.textContent));
  if (cvssH) {
    let el = cvssH.nextElementSibling, cvssTable = null;
    while (el) {
      if (/^H[1-4]$/.test(el.tagName)) break;
      if (el.tagName === "TABLE") { cvssTable = el; break; }
      cvssTable = el.querySelector("table"); if (cvssTable) break;
      el = el.nextElementSibling;
    }
    if (cvssTable) {
      let score = null, vector = null;
      for (const row of Array.from(cvssTable.querySelectorAll("tr"))) {
        const cells = Array.from(row.querySelectorAll("td,th")); if (cells.length < 2) continue;
        const label = cells[0].textContent.trim().toLowerCase();
        const valCell = cells[cells.length - 1];
        if (/overall\s*score|base\s*score/i.test(label)) {
          const s = parseFloat((valCell.querySelector("strong,b")?.textContent || valCell.textContent).trim());
          if (!isNaN(s) && s > 0 && s <= 10) score = s;
        }
        if (/^vector$/i.test(label) || /cvss\s*vector/i.test(label)) {
          const link = valCell.querySelector("a");
          for (const t of [(link?.textContent || "").trim(), valCell.textContent.trim()]) {
            if (/^(CVSS:|AV:)/i.test(t)) { vector = t; break; }
            const href = link?.getAttribute("href") || "";
            const m = decodeURIComponent(href).match(/vector=([^&]+)/);
            if (m) { vector = m[1]; break; }
          }
        }
      }
      if (score !== null && vector) {
        if (/^AV:/i.test(vector)) vector = "CVSS:3.0/" + vector;
        const version = detectCvssVersion(vector) || "v3.0";
        pushCvss(cvssList, version, { baseScore: score, vectorString: vector }, "PostgreSQL");
      } else if (score !== null) {
        pushCvss(cvssList, "v3.0", { baseScore: score, vectorString: null }, "PostgreSQL");
      }
    }
  }
  return { desc, cvssList, networkError: false, pageFound: !!desc || cvssList.length > 0 };
}
async function fetchOracleData(cve) {
  const url = `https://www.oracle.com/security-alerts/alert-${cve.toLowerCase()}.html`;
  const result = await proxyFetchWithStatus(url, "text");
  if (result.httpStatus === 0) return { desc: null, cvssList: [], networkError: true, pageFound: false };
  if (!result.data || result.httpStatus === 404) return { desc: null, cvssList: [], networkError: false, pageFound: false };
  const doc = new DOMParser().parseFromString(result.data, "text/html");
  let desc = null;
  const headings = Array.from(doc.querySelectorAll("h1,h2,h3,h4,dt,th,strong,b"));
  const descHeading = headings.find(el => /^description$/i.test(el.textContent.trim()));
  if (descHeading) {
    const paras = [];
    let sib = descHeading.closest("tr,dd,section,div")?.nextElementSibling
           || descHeading.parentElement?.nextElementSibling
           || descHeading.nextElementSibling;
    while (sib) {
      if (/^H[1-4]$/.test(sib.tagName)) break;
      const t = normalizeText(sib.textContent); if (t && t.length > 20) { paras.push(t); break; }
      sib = sib.nextElementSibling;
    }
    if (paras.length) desc = paras.join(" ");
  }
  if (!desc) {
    const containers = Array.from(doc.querySelectorAll("main,.content,.advisory-content,article,#content,[class*='detail'],.rc-content-main"));
    const pool = containers.length ? containers.flatMap(c => Array.from(c.querySelectorAll("p"))) : Array.from(doc.querySelectorAll("p"));
    for (const p of pool) {
      const t = normalizeText(p.textContent);
      if (t && t.length > 60 && !/(copyright|oracle corporation|all rights reserved)/i.test(t)) { desc = t; break; }
    }
  }
  return { desc, cvssList: [], networkError: false, pageFound: !!desc };
}

/* =================================================================
   XEN — cached JSON index + per-advisory HTML scraping
   ================================================================= */
let _xenJsonCache = null;
let _xenJsonFetch  = null;
async function getXenJson() {
  if (_xenJsonCache) return _xenJsonCache;
  if (!_xenJsonFetch) _xenJsonFetch = proxyFetch("https://xenbits.xen.org/xsa/xsa.json", "json");
  _xenJsonCache = await _xenJsonFetch;
  return _xenJsonCache;
}
async function fetchXenData(cve) {
  let xenJson;
  try { xenJson = await getXenJson(); } catch { return { desc: null, xsaNum: null, advisoryUrl: null, networkError: true, cveFound: false }; }
  if (!xenJson) return { desc: null, xsaNum: null, advisoryUrl: null, networkError: true, cveFound: false };

  // JSON structure: { "xsas": [ { "xsa": 26, "cves": ["CVE-2012-5510"], ... } ] }
  // Also handle bare array at root level for forward-compat.
  const cveUp   = cve.toUpperCase();
  const entries = Array.isArray(xenJson) ? xenJson.flatMap(e => e.xsas || e) 
                : Array.isArray(xenJson.xsas) ? xenJson.xsas
                : Object.values(xenJson);
   const entry = entries.find(e => {
    const list = e.cve || e.cves || e.CVEs || [];
    const arr = Array.isArray(list) ? list : [list];
    return arr.some(c => c.toUpperCase() === cveUp);
  });
  if (!entry) return { desc: null, xsaNum: null, advisoryUrl: null, networkError: false, cveFound: false };

  // CVE found in JSON — dot will be green regardless of description success
  const xsaNum      = entry.xsa;
  const advisoryUrl = `https://xenbits.xen.org/xsa/advisory-${xsaNum}.html`;

  // Fetch advisory HTML page
  const result = await proxyFetchWithStatus(advisoryUrl, "text");
  if (result.httpStatus === 0) return { desc: null, xsaNum, advisoryUrl, networkError: true, cveFound: true };
  if (!result.data || result.httpStatus === 404)
    return { desc: null, xsaNum, advisoryUrl, networkError: false, cveFound: true };

  // Extract text between "ISSUE DESCRIPTION\n===..." and next section header (e.g. "IMPACT\n===...")
  const doc      = new DOMParser().parseFromString(result.data, "text/html");
  const bodyText = doc.body ? doc.body.textContent : result.data;
  let desc = null;
  const m = bodyText.match(/ISSUE\s+DESCRIPTION[ \t]*\r?\n=+[ \t]*\r?\n([\s\S]*?)(?:\r?\n[ \t]*\r?\n[A-Z][A-Z0-9 _-]{1,30}[ \t]*\r?\n=+|-----END PGP)/);
  if (m) desc = normalizeText(m[1]);
  if (!desc) {
    // Fallback: grab first non-empty paragraph after the marker
    const m2 = bodyText.match(/ISSUE\s+DESCRIPTION[\s=]+([\s\S]{30,})/i);
    if (m2) {
      const block = m2[1].split(/\n\s*\n/)[0];
      if (block && block.trim().length > 20) desc = normalizeText(block);
    }
  }

  return { desc, xsaNum, advisoryUrl, networkError: false, cveFound: true };
}

/* =================================================================
   CISA KEV — cached at module level (one fetch shared across CVEs)
   ================================================================= */
let _cisaKevCache = null;
let _cisaKevFetch = null;
async function getCisaKev() {
  if (_cisaKevCache) return _cisaKevCache;
  if (!_cisaKevFetch) {
    _cisaKevFetch = proxyFetch("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "json");
  }
  const data = await _cisaKevFetch;
   if (data) _cisaKevCache = data;
  return data;
}
async function fetchCisaData(cve) {
  const kev = await getCisaKev();
  // Network error — could not fetch the KEV feed at all
  if (!kev) return { desc: null, cwes: null, notes: null, networkError: true, pageFound: false };
  const vulns = Array.isArray(kev.vulnerabilities) ? kev.vulnerabilities : [];
  const entry = vulns.find(v => (v.cveID || "").toUpperCase() === cve.toUpperCase());
  // CVE not in CISA KEV
  if (!entry) return { desc: null, cwes: null, notes: null, networkError: false, pageFound: false };
   
  let notes = entry.notes || null;
  if (typeof notes === 'string' && notes.includes(';')) {
    notes = notes.split(';').map(note => note.trim()).filter(note => note);
  }
  return {
    desc:        normalizeText(entry.shortDescription) || null,
    cwes:        entry.cwes || null,     // array of "CWE-NNN" strings (may be absent)
    notes:       notes,    // URL string or array
    networkError: false,
    pageFound:   true,
  };
}

/* =================================================================
   ENISA EUVD — European Union Vulnerability Database
   API endpoint: euvdservices.enisa.europa.eu/api/enisaid?id={CVE-ID}
   Returns a single entry object (or single-item array).
   Chip link → euvd.enisa.europa.eu/vulnerability/{EUVD-ID}
   ================================================================= */
async function fetchEnisaData(cve) {
  const apiUrl = `https://euvdservices.enisa.europa.eu/api/enisaid?id=${encodeURIComponent(cve)}`;
  const result = await proxyFetchWithStatus(apiUrl, "json");

  if (result.httpStatus === 0)
    return { desc: null, cvssList: [], refs: [], euvdId: null, euvdPageUrl: null, networkError: true, pageFound: false };
  if (!result.data || result.httpStatus !== 200)
    return { desc: null, cvssList: [], refs: [], euvdId: null, euvdPageUrl: null, networkError: false, pageFound: false };

  // Response may be a bare object, a single-element array, or wrapped {data: ...}
  const raw = result.data;
  let entry = null;
  if (Array.isArray(raw))              entry = raw[0] ?? null;
  else if (raw?.data && typeof raw.data === "object") entry = Array.isArray(raw.data) ? raw.data[0] : raw.data;
  else if (typeof raw === "object")    entry = raw;

  // Bail if empty object with no useful fields
  if (!entry) return { desc: null, cvssList: [], refs: [], euvdId: null, euvdPageUrl: null, networkError: false, pageFound: false };

  const euvdId = entry.id || entry.euvdId || entry.euvd_id || entry.vulnerabilityId || null;
  const euvdPageUrl = euvdId ? `https://euvd.enisa.europa.eu/vulnerability/${euvdId}` : null;

  const desc = normalizeText(
    entry.description || entry.summary || entry.title || entry.shortDescription || null
  ) || null;

  const rawScore  = entry.baseScore       ?? entry.cvssScore  ?? entry.cvssBaseScore ?? entry.score ?? null;
  const rawVector = entry.baseScoreVector ?? entry.cvssVector ?? entry.vectorString  ?? entry.vector ?? null;
  const rawVer    = entry.baseScoreVersion?? entry.cvssVersion?? entry.scoreVersion  ?? null;

  const cvssList = [];
  if (rawScore != null) {
    const score = parseFloat(rawScore);
    if (!isNaN(score) && score >= 0 && score <= 10) {
      const ver = (rawVector ? detectCvssVersion(rawVector) : null)
               || (rawVer    ? `v${String(rawVer).replace(/^v/i,"")}` : null);
      if (ver) {
        const normVec = rawVector ? (normalizeVector(ver, rawVector) || rawVector) : "";
        // Push directly to avoid pushCvss bailing on empty vector
        const ex = cvssList.find(c => c.version === ver && c.score === score && c.vector === normVec);
        if (ex) { if (!ex.sources.includes("ENISA")) ex.sources.push("ENISA"); }
        else     cvssList.push({ version: ver, score, vector: normVec, sources: ["ENISA"] });
      }
    }
  }

  let refs = [];
  if (Array.isArray(entry.references)) {
    refs = entry.references.map(r => (typeof r === "string" ? r : r?.url || "").trim()).filter(r => r.startsWith("http"));
  } else if (typeof entry.references === "string") {
    refs = entry.references.split(/[\n\s,]+/).map(r => r.trim()).filter(r => r.startsWith("http"));
  }

  const pageFound = !!(desc || cvssList.length || refs.length || euvdId);

  return { desc, cvssList, refs, euvdId, euvdPageUrl, networkError: false, pageFound };
}

/* =================================================================
   EPSS — Exploit Prediction Scoring System (FIRST.org)
   ================================================================= */

  /* EPSS batch cache — populated by prefetchEpssBatch() for multi-CVE searches */
const _epssCache = new Map();

async function prefetchEpssBatch(cves) {
  const d = new Date(); d.setMonth(d.getMonth() - 1);
  const prevDate = d.toISOString().slice(0, 10);
  const ids = cves.slice(0, 40).join(",");
  const [r, rPrev] = await Promise.all([
    proxyFetchWithStatus(`https://api.first.org/data/v1/epss?cve=${encodeURIComponent(ids)}`, "json"),
    proxyFetchWithStatus(`https://api.first.org/data/v1/epss?cve=${encodeURIComponent(ids)}&date=${prevDate}`, "json"),
  ]);
  const currMap = {}, prevMap = {};
  if (r.httpStatus === 200)    (r.data?.data    || []).forEach(e => { currMap[e.cve] = e; });
  if (rPrev.httpStatus === 200)(rPrev.data?.data || []).forEach(e => { prevMap[e.cve] = e; });
  cves.forEach(cve => {
    if (_epssCache.has(cve)) return;
    const curr = currMap[cve] ?? null;
    _epssCache.set(cve, {
      epss:         curr?.epss         ?? null,
      epss_prev:    prevMap[cve]?.epss ?? null,
      date:         curr?.date         ?? null,
      networkError: r.httpStatus === 0,
    });
  });
}

async function fetchEpssData(cve) {
  if (_epssCache.has(cve)) return _epssCache.get(cve);
  const d = new Date(); d.setMonth(d.getMonth() - 1);
  const prevDate = d.toISOString().slice(0, 10);
  const base = `https://api.first.org/data/v1/epss?cve=${encodeURIComponent(cve)}`;
  const [r, rPrev] = await Promise.all([
    proxyFetchWithStatus(base, "json"),
    proxyFetchWithStatus(`${base}&date=${prevDate}`, "json"),
  ]);
  if (r.httpStatus === 0) return { epss: null, epss_prev: null, date: null, networkError: true };
  const entry = r.data?.data?.[0];
  if (!entry) return { epss: null, epss_prev: null, date: null, networkError: false };
  const entryPrev = rPrev.httpStatus === 200 ? rPrev.data?.data?.[0] : null;
  return {
    epss:         entry.epss      ?? null,
    epss_prev:    entryPrev?.epss ?? null,
    date:         entry.date      ?? null,
    networkError: false,
  };
}

/* ── Danger colour scale: neutral → yellow → orange → red (t: 0→1) ──
   Stores danger level as data-t on the element so theme changes can
   reapply colours without re-fetching. */
function _epssColorStyle(t) {
  const isDark = document.documentElement.getAttribute("data-theme") === "dark";
  // Multi-stop hue interpolation (neutral blue-grey → yellow → orange → red)
  const stops = [
    [0.00, 220, 12],
    [0.12,  60, 55],
    [0.35,  30, 78],
    [0.65,  10, 85],
    [1.00,   0, 90],
  ];
  let lo = stops[0], hi = stops[stops.length - 1];
  for (let i = 0; i < stops.length - 1; i++) {
    if (t <= stops[i + 1][0]) { lo = stops[i]; hi = stops[i + 1]; break; }
  }
  const u   = lo[0] === hi[0] ? 0 : (t - lo[0]) / (hi[0] - lo[0]);
  const hue = Math.round(lo[1] + (hi[1] - lo[1]) * u);
  const sat = Math.round(lo[2] + (hi[2] - lo[2]) * u);
  const bgL = isDark ? Math.round(16 + t * 22)  : Math.round(96 - t * 44);
  const txL = isDark ? Math.round(68 + t * 24)  : Math.round(28 - t * 8);
  const brL = isDark ? Math.round(28 + t * 22)  : Math.round(76 - t * 28);
  return {
    background:   `hsl(${hue},${sat}%,${bgL}%)`,
    color:        `hsl(${hue},${Math.min(sat + 15, 95)}%,${txL}%)`,
    borderColor:  `hsl(${hue},${sat}%,${brL}%)`,
    borderStyle:  "groove",
    borderWidth:  "1px",
  };
}

function _applyEpssBadgeStyle(el) {
  const t = parseFloat(el.dataset.t ?? "0");
  const s = _epssColorStyle(t);
  el.style.background   = s.background;
  el.style.color        = s.color;
  el.style.borderColor  = s.borderColor;
  el.style.borderStyle  = s.borderStyle;
  el.style.borderWidth  = s.borderWidth;
}

/* Re-apply colours on all rendered EPSS badges (called on theme toggle) */
function refreshAllEpssColors() {
  document.querySelectorAll(".epss-badge[data-t]")
    .forEach(el => _applyEpssBadgeStyle(el));
}

function renderEpssInCard(cve, epssData) {
  const el = document.getElementById(`epss-${cve}`);
  if (!el) return;
  el.innerHTML = "";
  if (!epssData || epssData.epss == null) return;
  const epssScore = parseFloat(epssData.epss);
  if (isNaN(epssScore)) return;

  const sep = document.createElement("span"); sep.className = "sep"; sep.textContent = "•";
  el.appendChild(sep);

  const epssBadge = document.createElement("span");
  epssBadge.className = "epss-badge";
  epssBadge.dataset.t = String(epssScore);

  const valueEl = document.createElement("span"); valueEl.className = "epss-value";
  valueEl.textContent = (epssScore * 100).toFixed(2) + "%";
  epssBadge.appendChild(valueEl);

  // Trend indicator vs previous month
  const BASE_TITLE = "EPSS Score : The probability that the vulnerability will be exploited in the next 30 days.";
  if (epssData.epss_prev != null) {
    const prev = parseFloat(epssData.epss_prev);
    if (!isNaN(prev)) {
      const diff = epssScore - prev;
      const THRESH = 0.001;
      const trendEl = document.createElement("span");
      trendEl.className = "epss-trend";
      let trendDesc;
      if (diff > THRESH) {
        trendEl.textContent = "↑";
        trendEl.dataset.dir = "up";
        trendDesc = `↑ +${(diff * 100).toFixed(2)}% up compared last month`;
      } else if (diff < -THRESH) {
        trendEl.textContent = "↓";
        trendEl.dataset.dir = "down";
        trendDesc = `↓ ${(diff * 100).toFixed(2)}% down compared last month`;
      } else {
        trendEl.textContent = "-";
        trendEl.dataset.dir = "stable";
        trendDesc = "- stable compared last month";
      }
      epssBadge.appendChild(trendEl);
      epssBadge.title = `${BASE_TITLE}\n${trendDesc}`;
    }
  } else {
    epssBadge.title = BASE_TITLE;
  }
  _applyEpssBadgeStyle(epssBadge);

  const link = document.createElement("a");
  link.href = `https://api.first.org/data/v1/epss?cve=${encodeURIComponent(cve)}`;
  link.target = "_blank"; link.rel = "noopener noreferrer";
  link.appendChild(epssBadge);
  el.appendChild(link);
}


function extractDescFromCsaf(csaf) {
  if (!csaf) return null;
  const vuln = csaf?.document?.vulnerabilities?.[0] || csaf?.vulnerabilities?.[0];
  if (vuln) {
    const vn = Array.isArray(vuln.notes) ? vuln.notes : [];
    const vnt = vn.find(n => n.category === "description") || vn.find(n => n.category === "general");
    const s = normalizeText(Array.isArray(vnt?.text) ? vnt.text.join(" ") : vnt?.text); if (s) return s;
    const d = normalizeText(vuln.descriptions?.[0]?.value); if (d) return d;
  }
  const dn = Array.isArray(csaf?.document?.notes) ? csaf.document.notes : [];
  const dnt = dn.find(n => n.category === "description") || dn.find(n => n.category === "general") || dn.find(n => n.category === "summary");
  const ds = normalizeText(Array.isArray(dnt?.text) ? dnt.text.join(" ") : dnt?.text); if (ds) return ds;
  const title = normalizeText(csaf?.document?.title);
  if (title && !/^CVE-\d{4}-\d+$/i.test(title.trim())) return title;
  return null;
}
function extractDescFromRedHatLegacy(data) {
  if (!data) return null;
  for (const f of [data.description, data.details, data.cve?.description, data.advisory?.description, data.summary]) {
    const n = normalizeText(f); if (n) return n;
  }
  return null;
}
function extractSuseCvss(suseCsaf, source, cvssList) {
  if (!suseCsaf) return;
  const vulns = suseCsaf?.document?.vulnerabilities || suseCsaf?.vulnerabilities || [];
  vulns.forEach(vuln => (vuln.scores || []).forEach(se => {
    for (const [, obj] of Object.entries(se)) {
      if (!obj || typeof obj !== "object" || obj.baseScore == null) continue;
      const version = detectCvssVersion(obj.vectorString);
      if (version) pushCvss(cvssList, version, { baseScore: obj.baseScore, vectorString: obj.vectorString }, source);
    }
  }));
}

/* =================================================================
   DOM BUILDERS
   ================================================================= */
function createSkeletonCard(cve) {
  const card = document.createElement("div"); card.className = "cve-card";
  card.innerHTML = `<div class="card-top"><div class="card-meta-left">
    <div class="card-meta-row"><span class="assigner" style="opacity:.4">···</span><span class="sep">·</span><span class="date" style="opacity:.4">··/··/····</span></div>
    <div class="cve-title" style="opacity:.5">${esc(cve)}</div></div></div>
    <div class="skeleton-line" style="width:100%"></div>
    <div class="skeleton-line" style="width:82%"></div>
    <div class="skeleton-line" style="width:60%;margin-top:6px"></div>`;
  return card;
}
function createSourceBadge(name, url, cssClass) {
  const el = document.createElement(url ? "a" : "span");
  el.className = `source-badge badge-${(cssClass || name).toLowerCase()}`;
  el.textContent = name;
  if (url) { el.href = url; el.target = "_blank"; el.title = url; }
  return el;
}
function createDescRow(sources, text) {
  const row = document.createElement("div"); row.className = "desc-row";
  row.dataset.sources = sources.length ? sources.map(s => s.name).join(",") : "?";
  const left = document.createElement("div"); left.className = "desc-sources";
  if (sources.length) sources.forEach(s => left.appendChild(createSourceBadge(s.name, s.url, s.cssClass)));
  else { const ph = document.createElement("span"); ph.className = "source-badge"; ph.textContent = "?"; left.appendChild(ph); }
  const right = document.createElement("div"); right.className = "desc-text"; right.textContent = text || "";
  row.appendChild(left); row.appendChild(right); return row;
}
function createCvssBadge({ version, score, vector, sources }) {
  // FIRST calculator — hash fragment, no URL encoding needed
  const urlMap = {
    "v2.0": `https://nvd.nist.gov/vuln-metrics/cvss/v2-calculator?vector=${encodeURIComponent(vector||"")}&source=NIST`,
    "v3.0": `https://www.first.org/cvss/calculator/3.0#CVSS:3.0/${vector}`,
    "v3.1": `https://www.first.org/cvss/calculator/3.1#CVSS:3.1/${vector}`,
    "v4.0": `https://www.first.org/cvss/calculator/4.0#CVSS:4.0/${vector}`,
  };
  const a = document.createElement("a"); a.className = `cvss-badge ${cvssColorClass(score)}`;
  a.dataset.sources = sources.join(",");
  a.dataset.cvssVersion = version;
  a.href = (vector ? urlMap[version] : null) || "#";
  if (vector) { a.target = "_blank"; a.title = `Vector: ${vector}`; }
  else        { a.title = `Score provided by ${sources.join(", ")} — no vector available`; }
  a.innerHTML = `<span class="version">CVSS ${esc(version)}</span><span class="score">${esc(String(score))}</span><span class="sources">${esc(sources.join(", "))}</span>`;
  const wrap=document.createElement("div");
  wrap.className="cvss-badge-wrap";
  wrap.dataset.cvssVersion=version;
  wrap.appendChild(a);
  return wrap;
}

function createCweSection(cweList) {
  if (!cweList.length) return null;
  const section = document.createElement("div"); section.className = "cwe-section";
  cweList.forEach(({ id, name, desc, capecs, sources }) => {
    const num  = id.slice(4);
    const href = `https://cwe.mitre.org/data/definitions/${num}.html`;
    const entry = document.createElement("div"); entry.className = "cwe-entry";

    // CWE chip row
    const chipRow = document.createElement("div"); chipRow.className = "cwe-chip-row";
    const chip = document.createElement("a"); chip.className = "cwe-chip"; chip.href = href;
    chip.target = "_blank"; chip.title = desc || href;
    chip.dataset.sources = sources.join(",");
    const idEl = document.createElement("span"); idEl.className = "cwe-chip-id"; idEl.textContent = id; chip.appendChild(idEl);
    if (name) {
      const sep = document.createElement("span"); sep.className = "cwe-chip-sep"; sep.textContent = " — ";
      const nm  = document.createElement("span"); nm.className  = "cwe-chip-name"; nm.textContent = name;
      chip.appendChild(sep); chip.appendChild(nm);
    }
    const sr = document.createElement("span"); sr.className = "cwe-chip-srcs"; sr.textContent = ` (${sources.join(", ")})`; chip.appendChild(sr);
    chipRow.appendChild(chip);
    entry.appendChild(chipRow);

    // CAPEC row — always visible, connected by an arrow
    const capecList = capecs || [];
    if (capecList.length) {
      const capecRow = document.createElement("div"); capecRow.className = "capec-row";
      const arrow = document.createElement("span"); arrow.className = "capec-arrow"; arrow.textContent = "\u21b3";
      capecRow.appendChild(arrow);

      if (capecList.length === 1) {
        // Single CAPEC — show directly
        const a = document.createElement("a"); a.className = "capec-chip";
        a.href = `https://capec.mitre.org/data/definitions/${capecList[0]}.html`;
        a.target = "_blank"; a.rel = "noopener noreferrer";
        a.textContent = `CAPEC-${capecList[0]}`; capecRow.appendChild(a);
      } else {
        // Multiple CAPECs — collapsed behind a summary chip
        const chips = document.createElement("span"); chips.className = "capec-chips"; chips.hidden = true;
        capecList.forEach(cid => {
          const a = document.createElement("a"); a.className = "capec-chip";
          a.href = `https://capec.mitre.org/data/definitions/${cid}.html`;
          a.target = "_blank"; a.rel = "noopener noreferrer";
          a.textContent = `CAPEC-${cid}`; chips.appendChild(a);
        });
        const toggle = document.createElement("button"); toggle.className = "capec-toggle"; toggle.type = "button";
        toggle.textContent = `${capecList.length} CAPECs \u25be`;
        toggle.addEventListener("click", () => {
          const open = chips.hidden;
          chips.hidden = !open;
          toggle.textContent = open ? `${capecList.length} CAPECs \u25b4` : `${capecList.length} CAPECs \u25be`;
        });
        capecRow.appendChild(toggle);
        capecRow.appendChild(chips);
      }
      entry.appendChild(capecRow);
    }
    section.appendChild(entry);
  });
  return section;
}
function createLiveRefsDetails() {
  const details = document.createElement("details"); details.className = "refs-details";
  const summary = document.createElement("summary"); summary.className = "refs-summary";
  const arrow = document.createElement("span"); arrow.className = "refs-arrow"; arrow.textContent = "▶";
  const label = document.createElement("span"); label.textContent = "References";
  const count = document.createElement("span"); count.className = "refs-count"; count.textContent = "0";
  const spinner = document.createElement("span"); spinner.className = "refs-spinner"; spinner.textContent = "⟳"; spinner.title = "Loading…";
  summary.appendChild(arrow); summary.appendChild(label); summary.appendChild(count); summary.appendChild(spinner);
  details.appendChild(summary);
  const body = document.createElement("div"); body.className = "refs-body"; details.appendChild(body);
  return { details, countEl: count, spinnerEl: spinner, body };
}
function renderRefsBody(body, countEl, refs) {
  body.innerHTML = "";
  refs.forEach(({ url, sources }) => {
    const row = document.createElement("div"); row.className = "ref-row"; row.dataset.sources = sources.join(",");
    const badges = document.createElement("div"); badges.className = "ref-src-badges";
    sources.forEach(s => badges.appendChild(createSourceBadge(s, null)));
    const link = document.createElement("a"); link.className = "ref-link"; link.href = url; link.target = "_blank"; link.rel = "noopener noreferrer"; link.textContent = url;
    row.appendChild(badges); row.appendChild(link); body.appendChild(row);
  });
  countEl.textContent = refs.length;
}

/* =================================================================
   DESCRIPTION GROUPING
   Group all {name, url, text} items so that sources with identical
   text are merged into one row, regardless of which source they are.
   ================================================================= */
function buildDescGroups(items) {
  const groups = []; // [{text, sources:[{name,url}]}]
  for (const item of items) {
    if (!item.text) continue;
    const existing = groups.find(g => sameDescription(g.text, item.text));
    if (existing) {
      // Avoid duplicate badge for the same source name
      if (!existing.sources.find(s => s.name === item.name))
        existing.sources.push({ name: item.name, url: item.url });
    } else {
      groups.push({ text: item.text, sources: [{ name: item.name, url: item.url }] });
    }
  }
  return groups;
}

/* =================================================================
   RENDER CVE
   ================================================================= */
const displayedCVEs = new Set();
const cveData = new Map();

async function renderCve(cve, { skipStorage = false, cachedData = null } = {}) {
  const container = document.getElementById("cveResults");
  const skeleton = createSkeletonCard(cve);
  container.prepend(skeleton);

  const fp = {
    cveList: fetchCveListData(cve),
    nvd:     fetchNvdData(cve),
    rhOld: null, rhCsaf: null, suse:   null, debian: null,
    ubuntu: null, msrc:  null, amazon: null, lbo:    null,
    pg:    null, oracle: null, xen:    null, cisa:   null,
    enisa: null, epss:  null,
  };

  const ctx = {};
  let cvssBase = [];
  const excludedUrls = getExcludedRefUrls(cve);
  let refsBody, refsCountEl, refsSpinnerEl;

  function setDot(name, status, href) {
    const chip = document.getElementById(`dot-${name}-${cve}`);
    const dot = chip?.querySelector(".dot");
    if (dot) dot.className = `dot dot-${status}`;
    if (href && chip) chip.href = href;
        rebuildChipVisibility(cve);
  }

  // Rebuild all card sections from current ctx state
  function refreshCard() {
    // ── collect all (name, url, text) description candidates in priority order ──
    const allDescItems = [];
    const cveListDesc = normalizeText(ctx.cveListData?.containers?.cna?.descriptions?.[0]?.value);
    const cnaSource   = normalizeText(ctx.cveListData?.containers?.cna?.providerMetadata?.shortName) || "CVEList";
    const nvdDesc     = normalizeText(ctx.nvdData?.descriptions?.[0]?.value);
    const rhDesc      = extractDescFromCsaf(ctx.rhCsaf) || extractDescFromRedHatLegacy(ctx.rhOld);
    const suseDesc    = extractDescFromCsaf(ctx.suseCsaf);
    const debianDesc  = ctx.debianData?.desc || null;
    const ubuntuDesc  = ctx.ubuntuData?.desc || null;
    const ubuntuSpec  = ctx.ubuntuData?.ubuntuDesc || null;
    const msrcDesc    = ctx.msrcData?.desc || null;
    const amzDesc     = ctx.amazonData?.desc || null;
    const lboDesc     = ctx.libreofficeData?.desc || null;
    const pgDesc      = ctx.postgresData?.desc || null;
    const oracleDesc  = ctx.oracleData?.desc || null;
    const xenDesc     = ctx.xenData?.desc || null;
    const cisaDesc    = ctx.cisaData?.desc || null;
    const enisaDesc   = ctx.enisaData?.desc || null;
    
    if (cveListDesc) allDescItems.push({ name:"CVEList",      url:DESC_SOURCE_URLS.CVEList(cve),     text:cveListDesc });
    if (nvdDesc)     allDescItems.push({ name:"NVD",          url:DESC_SOURCE_URLS.NVD(cve),         text:nvdDesc });
    if (rhDesc)      allDescItems.push({ name:"RedHat",       url:DESC_SOURCE_URLS.RedHat(cve),      text:rhDesc });
    if (suseDesc)    allDescItems.push({ name:"SUSE",         url:DESC_SOURCE_URLS.SUSE(cve),        text:suseDesc });
    if (debianDesc)  allDescItems.push({ name:"Debian",       url:DESC_SOURCE_URLS.Debian(cve),      text:debianDesc });
    if (ubuntuDesc)  allDescItems.push({ name:"Ubuntu",       url:DESC_SOURCE_URLS.Ubuntu(cve),      text:ubuntuDesc });
    // Ubuntu-specific desc only if genuinely different from generic Ubuntu desc
    if (ubuntuSpec && !sameDescription(ubuntuSpec, ubuntuDesc))
                     allDescItems.push({ name:"Ubuntu",       url:DESC_SOURCE_URLS.Ubuntu(cve),      text:ubuntuSpec });
    if (msrcDesc)    allDescItems.push({ name:"Microsoft",    url:ctx.msrcData?.descSourceUrl || DESC_SOURCE_URLS.Microsoft(cve), text:msrcDesc });
    if (amzDesc)     allDescItems.push({ name:"Amazon",       url:DESC_SOURCE_URLS.Amazon(cve),      text:amzDesc });
    if (lboDesc)     allDescItems.push({ name:"LibreOffice",  url:DESC_SOURCE_URLS.LibreOffice(cve), text:lboDesc });
    if (pgDesc)      allDescItems.push({ name:"PostgreSQL",   url:DESC_SOURCE_URLS.PostgreSQL(cve),  text:pgDesc });
    if (oracleDesc)  allDescItems.push({ name:"Oracle",        url:DESC_SOURCE_URLS.Oracle(cve),      text:oracleDesc });
    if (xenDesc)     allDescItems.push({ name:"Xen",           url:DESC_SOURCE_URLS.Xen(cve), text:xenDesc });
    if (cisaDesc)    allDescItems.push({ name:"CISA",         url:DESC_SOURCE_URLS.CISA(cve),        text:cisaDesc });
    if (enisaDesc)   allDescItems.push({ name:"ENISA",        url:DESC_SOURCE_URLS.ENISA(cve),       text:enisaDesc });

    // Group — identical descriptions share one row, multiple source badges
    const groups = buildDescGroups(allDescItems);
    if (!groups.length) groups.push({ text: "No description available.", sources: [] });

    const dt = document.getElementById(`desc-${cve}`);
    if (dt) {
      dt.innerHTML = "";
      groups.forEach(g => dt.appendChild(createDescRow(g.sources, g.text)));
    }

    // ── CVSS ──
    const cvssAll = [...cvssBase];
    if (ctx.rhOld?.cvss3?.cvss3_base_score) pushCvss(cvssAll, "v3.1", { baseScore: ctx.rhOld.cvss3.cvss3_base_score, vectorString: ctx.rhOld.cvss3.cvss3_scoring_vector }, "RedHat");
    if (ctx.rhOld?.cvss?.cvss_base_score)   pushCvss(cvssAll, "v2.0", { baseScore: ctx.rhOld.cvss.cvss_base_score,  vectorString: ctx.rhOld.cvss.cvss_scoring_vector  }, "RedHat");
    extractSuseCvss(ctx.suseCsaf, "SUSE", cvssAll);
    (ctx.ubuntuData?.cvssList   || []).forEach(c => pushCvss(cvssAll, c.version, { baseScore: c.score, vectorString: c.vector }, "Ubuntu"));
    (ctx.msrcData?.cvssList     || []).forEach(c => pushCvss(cvssAll, c.version, { baseScore: c.score, vectorString: c.vector }, "Microsoft"));
    (ctx.amazonData?.cvssList   || []).forEach(c => pushCvss(cvssAll, c.version, { baseScore: c.score, vectorString: c.vector }, "Amazon"));
    (ctx.postgresData?.cvssList || []).forEach(c => pushCvss(cvssAll, c.version, { baseScore: c.score, vectorString: c.vector }, "PostgreSQL"));
    (ctx.oracleData?.cvssList   || []).forEach(c => pushCvss(cvssAll, c.version, { baseScore: c.score, vectorString: c.vector }, "Oracle"));
    // ENISA: bypass pushCvss (which requires a non-empty vector) — merge directly
    (ctx.enisaData?.cvssList || []).forEach(c => {
      if (c.vector) {
        pushCvss(cvssAll, c.version, { baseScore: c.score, vectorString: c.vector }, "ENISA");
      } else {
        const ex = cvssAll.find(x => x.version === c.version && x.score === c.score && x.vector === "");
        if (ex) { if (!ex.sources.includes("ENISA")) ex.sources.push("ENISA"); }
        else     cvssAll.push({ version: c.version, score: c.score, vector: "", sources: ["ENISA"] });
      }
    });
    sortCvss(cvssAll);

    const cvssEl = document.getElementById(`cvss-${cve}`);
    if (cvssEl) {
      cvssEl.innerHTML = "";
      if (cvssAll.length) cvssAll.forEach(e => cvssEl.appendChild(createCvssBadge(e)));
      else { const none = document.createElement("span"); none.style.cssText = "font-size:13px;color:var(--text-muted);font-style:italic;"; none.textContent = "No CVSS score available"; cvssEl.appendChild(none); }
      const cardEl = document.querySelector(`.cve-card[data-cve="${cve}"]`);
      if (cardEl) cardEl.dataset.cvssMax = String(computeVisibleCvssMax(cvssAll));
      applySortIfActive();
    }

    // ── Refs ──
    const notAff = computeNotAffected(ctx);
    const refs = collectRefs(ctx.cveListData, ctx.nvdData, ctx.rhCsaf, ctx.suseCsaf, ctx.msrcData?.vuln, ctx.ubuntuData?.rawData, ctx.cisaData, ctx.debianData?.refs, ctx.enisaData?.refs, notAff, excludedUrls);
    renderRefsBody(refsBody, refsCountEl, refs);

    applyFilter();
    applyRequirements();
  }

  async function refreshCwe() {
    const cweAll = collectCweList(ctx.cveListData, ctx.nvdData, ctx.rhCsaf, ctx.suseCsaf, ctx.msrcData?.vuln, ctx.cisaData);
    const db = await getCweDb();
    await Promise.all(cweAll.map(async c => {
      const num   = c.id.replace(/^CWE-/i, "");
      const entry = db?.[num];
      if (entry) {
        if (!c.name) c.name = entry.n || null;
        c.desc   = entry.d || null;
        c.capecs = entry.c || [];
      } else {
        c.capecs = [];
        if (!c.name) c.name = await fetchCweName(c.id); // fallback if DB missing
      }
    }));
    const cweContainer = document.getElementById(`cwe-${cve}`);
    if (cweContainer) { cweContainer.innerHTML = ""; const sec = createCweSection(cweAll); if (sec) cweContainer.appendChild(sec); }
    applyFilter();
  }

  try {
    let cveListData, nvdResult;
    if (cachedData) {
      // Restore from session cache — no HTTP call
      Object.assign(ctx, cachedData.ctx);
      cveListData = ctx.cveListData;
      nvdResult   = { data: ctx.nvdData, networkError: ctx.nvdNetworkError || false };
    } else {
      [cveListData, nvdResult] = await Promise.all([fp.cveList, fp.nvd]);
      ctx.cveListData = cveListData;
      ctx.nvdResult   = nvdResult;
      ctx.nvdData     = nvdResult?.data || null;
    }

    const hasCveList = !!cveListData;
    const cna        = cveListData?.containers?.cna || null;
    const assigner   = cveListData?.cveMetadata?.assignerShortName || null;
    const published  = cveListData?.cveMetadata?.datePublished || null;
    const dateStr    = published ? new Date(published).toLocaleDateString("en-GB") : null;
    const cveListDesc = normalizeText(cna?.descriptions?.[0]?.value);
    const nvdDesc     = normalizeText(ctx.nvdData?.descriptions?.[0]?.value);

    if (cachedData) {
      cvssBase.push(...(cachedData.cvssBase || []));
    } else {
      const cnaSource = normalizeText(cna?.providerMetadata?.shortName) || "CVEList";
      if (cna) extractMetricsFromContainer(cna, cnaSource, cvssBase);
      // ADP containers (CVE Program enrichment, introduced 2024-07-31)
      getAdpContainers(cveListData).forEach(adp => extractMetricsFromContainer(adp, "CISA-ADP", cvssBase));
      if (ctx.nvdData?.metrics) {
        const m = ctx.nvdData.metrics;
        (m.cvssMetricV40 || []).forEach(s => pushCvss(cvssBase, "v4.0", s.cvssData, "NVD"));
        (m.cvssMetricV31 || []).forEach(s => pushCvss(cvssBase, "v3.1", s.cvssData, "NVD"));
        (m.cvssMetricV30 || []).forEach(s => pushCvss(cvssBase, "v3.0", s.cvssData, "NVD"));
        (m.cvssMetricV2  || []).forEach(s => pushCvss(cvssBase, "v2.0", s.cvssData, "NVD"));
      }
      sortCvss(cvssBase);
    }

    // Build card DOM
    const card = document.createElement("div");
    card.className = hasCveList ? "cve-card" : "cve-card no-cvelist";
    card.dataset.cve     = cve;
    card.dataset.id      = cve;
    card.dataset.date    = published || "";
    card.dataset.cvssMax = "-1";
    if (!hasCveList) { const lbl = document.createElement("span"); lbl.className = "no-cvelist-label"; lbl.textContent = "Not in CVEList"; card.appendChild(lbl); }

    const cardTop = document.createElement("div"); cardTop.className = "card-top";
    const metaLeft = document.createElement("div"); metaLeft.className = "card-meta-left";
    const metaRow  = document.createElement("div"); metaRow.className  = "card-meta-row";
    if (hasCveList) {
      const el = document.createElement("a"); el.className = "assigner"; el.href = `https://www.cve.org/CVERecord?id=${cve}`; el.target = "_blank"; el.textContent = assigner || "unknown"; metaRow.appendChild(el);
    } else { const el = document.createElement("span"); el.className = "assigner unknown"; el.textContent = "UNKNOWN"; metaRow.appendChild(el); }
    if (dateStr) { const sep = document.createElement("span"); sep.className = "sep"; sep.textContent = "•"; metaRow.appendChild(sep); const de = document.createElement("span"); de.className = "date"; de.textContent = dateStr; metaRow.appendChild(de); }
    const epssPlaceholder = document.createElement("span"); epssPlaceholder.id = `epss-${cve}`; metaRow.appendChild(epssPlaceholder);
    metaLeft.appendChild(metaRow);
    const titleRow = document.createElement("div"); titleRow.className = "cve-title-row";
    const titleEl = document.createElement("div"); titleEl.className = "cve-title"; titleEl.textContent = cve;
    const shareBtn = document.createElement("button"); shareBtn.className = "card-action-btn card-share-btn"; shareBtn.type = "button"; shareBtn.title = "Copy shareable link";
    shareBtn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>`;
    shareBtn.addEventListener("click", () => {
      const url = buildPermalink([cve]);
      navigator.clipboard.writeText(url).catch(() => {
        const ta = document.createElement("textarea"); ta.value = url;
        ta.style.cssText = "position:fixed;opacity:0"; document.body.appendChild(ta);
        ta.select(); document.execCommand("copy"); document.body.removeChild(ta);
      });
      shareBtn.classList.add("copied");
      shareBtn.title = "Copied!";
      setTimeout(() => { shareBtn.classList.remove("copied"); shareBtn.title = "Copy shareable link"; }, 1800);
    });
    titleRow.appendChild(titleEl); titleRow.appendChild(shareBtn);
    metaLeft.appendChild(titleRow);
    cardTop.appendChild(metaLeft);

    const topRight = document.createElement("div"); topRight.className = "card-top-right";
    const actionsEl = document.createElement("div"); actionsEl.className = "card-actions";
    const refreshBtn = document.createElement("button"); refreshBtn.className = "card-action-btn card-refresh-btn"; refreshBtn.type = "button"; refreshBtn.title = "Refresh failed sources";
    refreshBtn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M23 4v6h-6"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>`;
    refreshBtn.addEventListener("click", () => refreshCve(cve));
    const deleteBtn = document.createElement("button"); deleteBtn.className = "card-action-btn card-delete-btn"; deleteBtn.type = "button"; deleteBtn.title = "Remove this CVE";
    deleteBtn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6M14 11v6"/><path d="M9 6V4h6v2"/></svg>`;
    deleteBtn.addEventListener("click", () => deleteCve(cve));
    actionsEl.appendChild(refreshBtn); actionsEl.appendChild(deleteBtn);
    const chipsRight = document.createElement("div"); chipsRight.className = "card-chips-right";
    for (const src of SOURCE_CONFIG) {
      const chip = document.createElement("a"); chip.className = "source-chip"; chip.href = src.url(cve); chip.target = "_blank"; chip.id = `dot-${src.name}-${cve}`; chip.dataset.source = src.name;
      const dot = document.createElement("span"); dot.className = "dot dot-wait";
      chip.appendChild(dot); chip.appendChild(document.createTextNode(src.name)); chipsRight.appendChild(chip);
    }
    topRight.appendChild(actionsEl); topRight.appendChild(chipsRight);
    cardTop.appendChild(topRight); card.appendChild(cardTop);

    // Initial description from phase-1 (CVEList + NVD)
    const mainDescInit = cveListDesc || nvdDesc || "Loading…";
    const initMainSrcs = [];
    if (cveListDesc && sameDescription(cveListDesc, mainDescInit)) initMainSrcs.push({ name:"CVEList", url:DESC_SOURCE_URLS.CVEList(cve) });
    if (nvdDesc     && sameDescription(nvdDesc,     mainDescInit)) initMainSrcs.push({ name:"NVD",     url:DESC_SOURCE_URLS.NVD(cve) });
    const descTableEl = document.createElement("div"); descTableEl.className = "desc-table"; descTableEl.id = `desc-${cve}`;
    descTableEl.appendChild(createDescRow(initMainSrcs, mainDescInit)); card.appendChild(descTableEl);

    // Initial CVSS
    const cvssEl = document.createElement("div"); cvssEl.className = "cvss-section"; cvssEl.id = `cvss-${cve}`;
    if (cvssBase.length) cvssBase.forEach(e => cvssEl.appendChild(createCvssBadge(e)));
    else { const none = document.createElement("span"); none.style.cssText = "font-size:13px;color:var(--text-muted);font-style:italic;"; none.textContent = "No CVSS score available"; cvssEl.appendChild(none); }
    card.appendChild(cvssEl);

    // CWE placeholder
    const cweContainerEl = document.createElement("div"); cweContainerEl.id = `cwe-${cve}`;
    const cweInit = createCweSection(collectCweList(cveListData, ctx.nvdData, null, null, null, null));
    if (cweInit) cweContainerEl.appendChild(cweInit);
    card.appendChild(cweContainerEl);

    // References
    const { details: refsDetails, countEl, spinnerEl, body: rb } = createLiveRefsDetails();
    refsBody = rb; refsCountEl = countEl; refsSpinnerEl = spinnerEl;
    const initRefs = collectRefs(cveListData, ctx.nvdData, null, null, null, null, null, null, null, new Set(), excludedUrls);
    renderRefsBody(refsBody, refsCountEl, initRefs);
    card.appendChild(refsDetails);

    container.replaceChild(card, skeleton);

    // Set initial cvssMax from Phase 1 scores
    if (cvssBase.length) card.dataset.cvssMax = String(computeVisibleCvssMax(cvssBase));

    // NVD dot immediately
    setDot("NVD", ctx.nvdResult?.networkError ? "networkerror" : ctx.nvdResult?.data ? "ok" : "fail");

    refreshCwe();

    cveData.set(cve, { ctx, cvssBase, excludedUrls, setDot, refreshCard, refreshCwe, refsSpinnerEl });
    if (!skipStorage) storageAddCve(cve);
    updateClearSection();

    if (cachedData) {
      // ── Restore full card from session cache, no Phase 2 fetches ──
      refreshCard();
      refreshCwe();
      // cvssMax déjà mis à jour par refreshCard via computeVisibleCvssMax
      SOURCE_CONFIG.forEach(s => {
        const status = cachedData.dotStatuses?.[s.name] || "fail";
        const url    = cachedData.dotUrls?.[s.name];
        setDot(s.name, status, url || undefined);
      });
      renderEpssInCard(cve, ctx.epssData);
      refsSpinnerEl.style.display = "none";
      return;
    }

    /* ---- Phase 2: secondary sources ----
    ------------------------------------------------------------------ */
    fp.rhOld  = fetchRedHatData(cve);
    fp.rhCsaf = fetchRedHatCsaf(cve);
    fp.suse   = fetchSuseCsaf(cve);
    fp.debian = fetchDebianDescription(cve);
    fp.ubuntu = fetchUbuntuData(cve);
    fp.msrc   = fetchMsrcData(cve);
    fp.amazon = fetchAmazonData(cve);
    fp.lbo    = fetchLibreOfficeData(cve);
    fp.pg     = fetchPostgreSQLData(cve);
    fp.oracle = fetchOracleData(cve);
    fp.xen    = fetchXenData(cve);
    fp.cisa   = fetchCisaData(cve);
    fp.enisa  = fetchEnisaData(cve);

    // RedHat
    let rhPending = 2;
    function onRhDone() {
      refreshCard();
      if (--rhPending > 0) return;
      const vuln = ctx.rhCsaf?.document?.vulnerabilities?.[0] || ctx.rhCsaf?.vulnerabilities?.[0];
      if (vuln?.product_status) {
        const ps = vuln.product_status;
        const aff = (ps.known_affected||[]).length + (ps.fixed||[]).length + (ps.under_investigation||[]).length;
        const notAff = (ps.known_not_affected||[]).length;
        setDot("RedHat", aff > 0 ? "ok" : notAff > 0 ? "notaffected" : "ok");
      } else if (ctx.rhOld) {
        const hasScore    = !!(ctx.rhOld.cvss?.cvss_base_score || ctx.rhOld.cvss3?.cvss3_base_score);
        const hasSeverity = !!ctx.rhOld.threat_severity;
        const stmtNotAff  = /does not affect/i.test(ctx.rhOld.statement || "");
        if (hasScore || hasSeverity) setDot("RedHat", "ok");
        else if (stmtNotAff)         setDot("RedHat", "notaffected");
        else if (ctx.rhOld.bugzilla)  setDot("RedHat", "ok");
        else                          setDot("RedHat", "notaffected");
      } else {
        proxyFetchWithStatus(`https://access.redhat.com/security/cve/${encodeURIComponent(cve)}`, "text").then(r => {
          if (r.httpStatus === 0) { setDot("RedHat", "networkerror"); return; }
          if (!r.data || r.httpStatus === 404) { setDot("RedHat", "fail"); return; }
          const html = r.data;
          if (/does not affect red hat/i.test(html)) setDot("RedHat", "notaffected");
          else if (/threat_severity|affected_release|cve-severity|bugzilla\.redhat\.com/i.test(html)) setDot("RedHat", "ok");
          else setDot("RedHat", "fail");
        });
      }
      refreshCwe();
    }
    fp.rhOld.then(d  => { ctx.rhOld  = d  ?? null; onRhDone(); }).catch(() => { ctx.rhOld  = null; onRhDone(); });
    fp.rhCsaf.then(d => { ctx.rhCsaf = d  ?? null; onRhDone(); }).catch(() => { ctx.rhCsaf = null; onRhDone(); });

    fp.suse.then(async r => {
      ctx.suseCsaf = r?.data ?? null; refreshCard();
      if (r?.networkError) setDot("SUSE", "networkerror");
      else if (ctx.suseCsaf) setDot("SUSE", "ok");
      else {
        const pageStatus = await checkUrl(SOURCE_CONFIG.find(s => s.name === "SUSE").url(cve));
        setDot("SUSE", pageStatus === "ok" ? "notaffected" : pageStatus);
      }
      refreshCwe();
    }).catch(() => { ctx.suseCsaf = null; setDot("SUSE", "networkerror"); });

    fp.debian.then(d => {
      ctx.debianData = d ?? null; refreshCard();
      if (ctx.debianData?.networkError)             setDot("Debian", "networkerror");
      else if (!ctx.debianData)                      setDot("Debian", "fail");
      else if (ctx.debianData.notAffected === true)   setDot("Debian", "notaffected");
      else if (ctx.debianData.desc || ctx.debianData.notAffected === false) setDot("Debian", "ok");
      else                                           setDot("Debian", "fail");
    }).catch(() => { ctx.debianData = null; setDot("Debian", "networkerror"); });

    fp.ubuntu.then(d => {
      ctx.ubuntuData = d ?? null; refreshCard();
      if (ctx.ubuntuData?.networkError)               setDot("Ubuntu", "networkerror");
      else if (ctx.ubuntuData?.notAffected === false)  setDot("Ubuntu", "ok");
      else if (ctx.ubuntuData?.notAffected === true)   setDot("Ubuntu", "notaffected");
      else                                             setDot("Ubuntu", "fail");
    }).catch(() => { ctx.ubuntuData = null; setDot("Ubuntu", "networkerror"); });

    fp.msrc.then(d => {
      ctx.msrcData = d ?? null; refreshCard();
      setDot("Microsoft", ctx.msrcData?.dotStatus || "fail", ctx.msrcData?.dotUrl);
      refreshCwe();
    }).catch(() => { ctx.msrcData = null; setDot("Microsoft", "networkerror"); });

    fp.amazon.then(d => {
      ctx.amazonData = d ?? null; refreshCard();
      if (ctx.amazonData?.networkError)                                  setDot("Amazon", "networkerror");
      else if (!ctx.amazonData?.pageFound)                               setDot("Amazon", "fail");
      else if (ctx.amazonData?.desc || ctx.amazonData?.cvssList?.length) setDot("Amazon", "ok");
      else                                                               setDot("Amazon", "notaffected");
    }).catch(() => { ctx.amazonData = null; setDot("Amazon", "networkerror"); });

    fp.lbo.then(d => {
      ctx.libreofficeData = d ?? null; refreshCard();
      if (ctx.libreofficeData?.networkError)    setDot("LibreOffice", "networkerror");
      else if (!ctx.libreofficeData?.pageFound) setDot("LibreOffice", "fail");
      else if (ctx.libreofficeData?.desc)       setDot("LibreOffice", "ok");
      else                                      setDot("LibreOffice", "notaffected");
    }).catch(() => { ctx.libreofficeData = null; setDot("LibreOffice", "networkerror"); });

    fp.pg.then(d => {
      ctx.postgresData = d ?? null; refreshCard();
      if (ctx.postgresData?.networkError)                                    setDot("PostgreSQL", "networkerror");
      else if (!ctx.postgresData?.pageFound)                                 setDot("PostgreSQL", "fail");
      else if (ctx.postgresData?.desc || ctx.postgresData?.cvssList?.length) setDot("PostgreSQL", "ok");
      else                                                                    setDot("PostgreSQL", "notaffected");
    }).catch(() => { ctx.postgresData = null; setDot("PostgreSQL", "networkerror"); });

    fp.oracle.then(d => {
      ctx.oracleData = d ?? null; refreshCard();
      if (ctx.oracleData?.networkError)                                  setDot("Oracle", "networkerror");
      else if (!ctx.oracleData?.pageFound)                               setDot("Oracle", "fail");
      else if (ctx.oracleData?.desc || ctx.oracleData?.cvssList?.length) setDot("Oracle", "ok");
      else                                                               setDot("Oracle", "notaffected");
    }).catch(() => { ctx.oracleData = null; setDot("Oracle", "networkerror"); });

    fp.xen.then(d => {
      ctx.xenData = d ?? null;
      // Exclude the advisory URL from refs — it's already surfaced on the Xen dot badge
      if (ctx.xenData?.advisoryUrl) excludedUrls.add(ctx.xenData.advisoryUrl);
      refreshCard();
      if (ctx.xenData?.networkError)   setDot("Xen", "networkerror");
      else if (ctx.xenData?.cveFound)  setDot("Xen", "ok", ctx.xenData.advisoryUrl);
      else                             setDot("Xen", "fail");
    }).catch(() => { ctx.xenData = null; setDot("Xen", "networkerror"); });

    fp.cisa.then(d => {
      ctx.cisaData = d ?? null; refreshCard(); refreshCwe();
      if (ctx.cisaData?.networkError)    setDot("CISA", "networkerror");
      else if (ctx.cisaData?.pageFound)  setDot("CISA", "ok");
      else                               setDot("CISA", "fail");
    }).catch(() => { ctx.cisaData = null; setDot("CISA", "networkerror"); });

    fp.enisa.then(d => {
      ctx.enisaData = d ?? null;
      // Exclude the EUVD page URL from refs (already surfaced via dot badge)
      if (ctx.enisaData?.euvdPageUrl) excludedUrls.add(ctx.enisaData.euvdPageUrl);
      refreshCard();
      if (ctx.enisaData?.networkError)    setDot("ENISA", "networkerror");
      else if (ctx.enisaData?.pageFound)  setDot("ENISA", "ok", ctx.enisaData.euvdPageUrl);
      else                                setDot("ENISA", "fail");
    }).catch(() => { ctx.enisaData = null; setDot("ENISA", "networkerror"); });

    fp.epss = fetchEpssData(cve);
    fp.epss.then(d => { ctx.epssData = d ?? null; renderEpssInCard(cve, ctx.epssData); })
            .catch(() => { ctx.epssData = null; });

    Promise.allSettled([fp.rhOld, fp.rhCsaf, fp.suse, fp.debian, fp.ubuntu, fp.msrc, fp.amazon, fp.lbo, fp.pg, fp.oracle, fp.xen, fp.cisa, fp.enisa, fp.epss])
      .then(() => { refsSpinnerEl.style.display = "none"; sessionSave(cve, ctx, cvssBase); });

  } catch (err) {
    const errDiv = document.createElement("div"); errDiv.className = "cve-error"; errDiv.textContent = `⚠ ${err.message}`;
    try { container.replaceChild(errDiv, skeleton); } catch { container.prepend(errDiv); }
  }
}

/* =================================================================
   ENVIRONMENTAL REQUIREMENTS — global Options panel
   ================================================================= */
const _C3W_R = {
  AV:{N:0.85,A:0.62,L:0.55,P:0.2}, AC:{L:0.77,H:0.44},
  PR_U:{N:0.85,L:0.62,H:0.27}, PR_C:{N:0.85,L:0.68,H:0.5},
  UI:{N:0.85,R:0.62}, CIA:{N:0,L:0.22,H:0.56}, REQ:{X:1,L:0.5,M:1,H:1.5},
};
function _cR3(v){const n=Math.round(v*100000);return n%10000===0?n/100000:(Math.floor(n/10000)+1)/10;}

function cvss3ReqScore(vec, state) {
  const w=_C3W_R;
  const CR=w.REQ[state.CR]??1, IR=w.REQ[state.IR]??1, AR=w.REQ[state.AR]??1;
  const ov=(base,k)=>{const v=state[k];return(v&&v!=='X')?v:base;};
  const mAV=ov(vec.AV,'MAV'),mAC=ov(vec.AC,'MAC'),mPR=ov(vec.PR,'MPR');
  const mUI=ov(vec.UI,'MUI'),mS=ov(vec.S||'U','MS');
  const mC=ov(vec.C,'MC'),mI=ov(vec.I,'MI'),mA=ov(vec.A,'MA');
  const ISC=Math.min(1-(1-(w.CIA[mC]??0)*CR)*(1-(w.CIA[mI]??0)*IR)*(1-(w.CIA[mA]??0)*AR),0.915);
  const mImp=mS==='C'?7.52*(ISC-0.029)-3.25*Math.pow(ISC-0.02,15):6.42*ISC;
  if(mImp<=0)return 0;
  const wPR=(mS==='C'?w.PR_C:w.PR_U)[mPR]??0;
  const exp=8.22*(w.AV[mAV]??0)*(w.AC[mAC]??0)*wPR*(w.UI[mUI]??0);
  const raw=mS==='C'?Math.min(1.08*(mImp+exp),10):Math.min(mImp+exp,10);
  return Math.min(_cR3(raw),10);
}

const _C2W_R = {
  AV:{L:0.395,A:0.646,N:1.0}, AC:{H:0.35,M:0.61,L:0.71},
  Au:{M:0.45,S:0.56,N:0.704}, CIA:{N:0,P:0.275,C:0.660},
  REQ:{X:1.0,L:0.5,M:1.0,H:1.51},
};

function cvss2ReqScore(vec, state) {
  const w = _C2W_R;
  const CR = w.REQ[state.CR] ?? 1.0;
  const IR = w.REQ[state.IR] ?? 1.0;
  const AR = w.REQ[state.AR] ?? 1.0;
  const adjImp = Math.min(10, 10.41*(1-(1-(w.CIA[vec.C]??0)*CR)*(1-(w.CIA[vec.I]??0)*IR)*(1-(w.CIA[vec.A]??0)*AR)));
  if (adjImp <= 0) return 0;
  const exp = 20*(w.AV[vec.AV]??0)*(w.AC[vec.AC]??0)*(w.Au[vec.Au]??0);
  return Math.round(Math.min(10,(0.6*adjImp+0.4*exp-1.5)*1.176)*10)/10;
}

/* CVSS 4.0 score lookup table (EQ1+EQ2+EQ3+EQ4+EQ5+EQ6) — FIRST reference */
// Localisation : remplacer le bloc   const _V4_SCORES={...};
const _V4_SCORES={
  "000000":10,"000001":9.9,"000010":9.8,"000011":9.5,"000020":9.5,"000021":9.2,
  "000100":10,"000101":9.6,"000110":9.3,"000111":8.7,"000120":9.1,"000121":8.1,
  "000200":9.3,"000201":9,"000210":8.9,"000211":8,"000220":8.1,"000221":6.8,
  "001000":9.8,"001001":9.5,"001010":9.5,"001011":9.2,"001020":9,"001021":8.4,
  "001100":9.3,"001101":9.2,"001110":8.9,"001111":8.1,"001120":8.1,"001121":6.5,
  "001200":8.8,"001201":8,"001210":7.8,"001211":7,"001220":6.9,"001221":4.8,
  "002001":9.2,"002011":8.2,"002021":7.2,"002101":7.9,"002111":6.9,"002121":5,
  "002201":6.9,"002211":5.5,"002221":2.7,
  "010000":9.9,"010001":9.7,"010010":9.5,"010011":9.2,"010020":9.2,"010021":8.5,
  "010100":9.5,"010101":9.1,"010110":9,"010111":8.3,"010120":8.4,"010121":7.1,
  "010200":9.2,"010201":8.1,"010210":8.2,"010211":7.1,"010220":7.2,"010221":5.3,
  "011000":9.5,"011001":9.3,"011010":9.2,"011011":8.5,"011020":8.5,"011021":7.3,
  "011100":9.2,"011101":8.2,"011110":8,"011111":7.2,"011120":7,"011121":5.9,
  "011200":8.4,"011201":7,"011210":7.1,"011211":5.2,"011220":5,"011221":3,
  "012001":8.6,"012011":7.5,"012021":5.2,"012101":7.1,"012111":5.2,"012121":2.9,
  "012201":6.3,"012211":2.9,"012221":1.7,
  "100000":9.8,"100001":9.5,"100010":9.4,"100011":8.7,"100020":9.1,"100021":8.1,
  "100100":9.4,"100101":8.9,"100110":8.6,"100111":7.4,"100120":7.7,"100121":6.4,
  "100200":8.7,"100201":7.5,"100210":7.4,"100211":6.3,"100220":6.3,"100221":4.9,
  "101000":9.4,"101001":8.9,"101010":8.8,"101011":7.7,"101020":7.6,"101021":6.7,
  "101100":8.6,"101101":7.6,"101110":7.4,"101111":5.8,"101120":5.9,"101121":5,
  "101200":7.2,"101201":5.7,"101210":5.7,"101211":5.2,"101220":5.2,"101221":2.5,
  "102001":8.3,"102011":7,"102021":5.4,"102101":6.5,"102111":5.8,"102121":2.6,
  "102201":5.3,"102211":2.1,"102221":1.3,
  "110000":9.5,"110001":9,"110010":8.8,"110011":7.6,"110020":7.6,"110021":7,
  "110100":9,"110101":7.7,"110110":7.5,"110111":6.2,"110120":6.1,"110121":5.3,
  "110200":7.7,"110201":6.6,"110210":6.8,"110211":5.9,"110220":5.2,"110221":3,
  "111000":8.9,"111001":7.8,"111010":7.6,"111011":6.7,"111020":6.2,"111021":5.8,
  "111100":7.4,"111101":5.9,"111110":5.7,"111111":5.7,"111120":4.7,"111121":2.3,
  "111200":6.1,"111201":5.2,"111210":5.7,"111211":2.9,"111220":2.4,"111221":1.6,
  "112001":7.1,"112011":5.9,"112021":3,"112101":5.8,"112111":2.6,"112121":1.5,
  "112201":2.3,"112211":1.3,"112221":0.6,
  "200000":9.3,"200001":8.7,"200010":8.6,"200011":7.2,"200020":7.5,"200021":5.8,
  "200100":8.6,"200101":7.4,"200110":7.4,"200111":6.1,"200120":5.6,"200121":3.4,
  "200200":7,"200201":5.4,"200210":5.2,"200211":4,"200220":4,"200221":2.2,
  "201000":8.5,"201001":7.5,"201010":7.4,"201011":5.5,"201020":6.2,"201021":5.1,
  "201100":7.2,"201101":5.7,"201110":5.5,"201111":4.1,"201120":4.6,"201121":1.9,
  "201200":5.3,"201201":3.6,"201210":3.4,"201211":1.9,"201220":1.9,"201221":0.8,
  "202001":6.4,"202011":5.1,"202021":2,"202101":4.7,"202111":2.1,"202121":1.1,
  "202201":2.4,"202211":0.9,"202221":0.4,
  "210000":8.8,"210001":7.5,"210010":7.3,"210011":5.3,"210020":6,"210021":5,
  "210100":7.3,"210101":5.5,"210110":5.9,"210111":4,"210120":4.1,"210121":2,
  "210200":5.4,"210201":4.3,"210210":4.5,"210211":2.2,"210220":2,"210221":1.1,
  "211000":7.5,"211001":5.5,"211010":5.8,"211011":4.5,"211020":4,"211021":2.1,
  "211100":6.1,"211101":5.1,"211110":4.8,"211111":1.8,"211120":2,"211121":0.9,
  "211200":4.6,"211201":1.8,"211210":1.7,"211211":0.7,"211220":0.8,"211221":0.2,
  "212001":5.3,"212011":2.4,"212021":1.4,"212101":2.4,"212111":1.2,"212121":0.5,
  "212201":1,"212211":0.3,"212221":0.1,
};

/* CVSS 4.0 — FIRST reference data (maxSeverity + maxComposed vectors) */
const _V4_MAX_SEV = {
  eq1:    {0:1,   1:4,   2:5},
  eq2:    {0:1,   1:2},
  eq3eq6: {0:{0:7,1:6}, 1:{0:8,1:8}, 2:{1:10}},
  eq4:    {0:6,   1:5,   2:4},
  eq5:    {0:1,   1:1,   2:1},
};
const _V4_MAX_VEC = {
  eq1: {
    0:['AV:N/PR:N/UI:N/'],
    1:['AV:A/PR:N/UI:N/','AV:N/PR:L/UI:N/','AV:N/PR:N/UI:P/'],
    2:['AV:P/PR:N/UI:N/','AV:A/PR:L/UI:P/'],
  },
  eq2: {
    0:['AC:L/AT:N/'],
    1:['AC:H/AT:N/','AC:L/AT:P/'],
  },
  eq3: {
    0:{0:['VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/'],
       1:['VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/','VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/']},
    1:{0:['VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/','VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/'],
       1:['VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/','VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/',
          'VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/','VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/',
          'VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/']},
    2:{1:['VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/']},
  },
  eq4: {
    0:['SC:H/SI:S/SA:S/'],
    1:['SC:H/SI:H/SA:H/'],
    2:['SC:L/SI:L/SA:L/'],
  },
  eq5: {
    0:['E:A/'],
    1:['E:P/'],
    2:['E:U/'],
  },
};

/**
 * CVSS 4.0 environmental score from CR/IR/AR only (all M-metrics = X → use base).
 * Uses FIRST lookup table. Missing combinations (impossible vectors) return null.
 * Note: does not implement mean-distance interpolation; result within ±0.2 of true score.
 */
/* ─── CVSS 4.0 environmental score — algorithme officiel FIRST §7.4 ─────────
   Port fidèle de cvss4/dist/bundle.umd.js (npm:cvss4).
   Autonome, sans dépendance réseau, 100% conforme FIRST.
   ─────────────────────────────────────────────────────────────────────────── */
function cvss4ReqScore(vec, state) {
  const mG=(sk,vk)=>{const sv=state[sk];return(sv&&sv!=='X')?sv:vec[vk||sk];};
  const sel = {
    AV:vec.AV||'N', PR:vec.PR||'N', UI:vec.UI||'N',
    AC:vec.AC||'L', AT:vec.AT||'N',
    VC:vec.VC||'N', VI:vec.VI||'N', VA:vec.VA||'N',
    SC:vec.SC||'N', SI:vec.SI||'N', SA:vec.SA||'N',
    E: vec.E  ||'X',
    CR:state.CR||'X', IR:state.IR||'X', AR:state.AR||'X',
    MAV:mG('MAV'),  MAC:mG('MAC'),  MAT:mG('MAT'),
    MPR:mG('MPR'),  MUI:mG('MUI4','MUI'),
    MVC:mG('MVC'),  MVI:mG('MVI'),  MVA:mG('MVA'),
    MSC:mG('MSC'),  MSI:mG('MSI'),  MSA:mG('MSA'),
  };

  // m() — resolve effective metric value (handles X defaults + modified metrics)
  const m = (metric) => {
    const v = sel[metric];
    if (metric==='E'  && v==='X') return 'A';
    if (metric==='CR' && v==='X') return 'H';
    if (metric==='IR' && v==='X') return 'H';
    if (metric==='AR' && v==='X') return 'H';
    // Modified base metric overrides base (if defined and not X)
    const mod = sel['M'+metric];
    if (mod !== undefined && mod !== 'X') return mod;
    return v;
  };

  // Zero-impact shortcut
  if (['VC','VI','VA','SC','SI','SA'].every(k=>m(k)==='N')) return 0;

  // ── Macro vector (EQ1–EQ6) ──────────────────────────────────────────────
  let eq1,eq2,eq3,eq4,eq5,eq6;
  // EQ1
  if (m('AV')==='N'&&m('PR')==='N'&&m('UI')==='N') eq1=0;
  else if ((m('AV')==='N'||m('PR')==='N'||m('UI')==='N')&&m('AV')!=='P') eq1=1;
  else eq1=2;
  // EQ2
  eq2=(m('AC')==='L'&&m('AT')==='N')?0:1;
  // EQ3
  if (m('VC')==='H'&&m('VI')==='H') eq3=0;
  else if (m('VC')==='H'||m('VI')==='H'||m('VA')==='H') eq3=1;
  else eq3=2;
  // EQ4 — uses MSI/MSA for safety override
  if (m('MSI')==='S'||m('MSA')==='S') eq4=0;
  else if (m('SC')==='H'||m('SI')==='H'||m('SA')==='H') eq4=1;
  else eq4=2;
  // EQ5
  eq5=m('E')==='A'?0:m('E')==='P'?1:2;
  // EQ6
  eq6=((m('CR')==='H'&&m('VC')==='H')||(m('IR')==='H'&&m('VI')==='H')||(m('AR')==='H'&&m('VA')==='H'))?0:1;

  const macroKey=`${eq1}${eq2}${eq3}${eq4}${eq5}${eq6}`;
  let value=_V4_SCORES[macroKey];
  if (value==null) return null;

  // ── Next-lower macro scores (NaN if combination does not exist) ──────────
  const s=k=>_V4_SCORES[k]??NaN;
  const eq1NL=s(`${eq1+1}${eq2}${eq3}${eq4}${eq5}${eq6}`);
  const eq2NL=s(`${eq1}${eq2+1}${eq3}${eq4}${eq5}${eq6}`);
  let eq3eq6NL=NaN;
  if (eq3===0&&eq6===0) {
    const l=s(`${eq1}${eq2}${eq3}${eq4}${eq5}${eq6+1}`);
    const r=s(`${eq1}${eq2}${eq3+1}${eq4}${eq5}${eq6}`);
    eq3eq6NL=(!isNaN(l)&&!isNaN(r))?(l>r?l:r):(!isNaN(l)?l:r);
  } else if (eq3===0&&eq6===1) eq3eq6NL=s(`${eq1}${eq2}${eq3+1}${eq4}${eq5}${eq6}`);
  else if (eq3===1&&eq6===0) eq3eq6NL=s(`${eq1}${eq2}${eq3}${eq4}${eq5}${eq6+1}`);
  else if (eq3===1&&eq6===1) eq3eq6NL=s(`${eq1}${eq2}${eq3+1}${eq4}${eq5}${eq6+1}`);
  else eq3eq6NL=s(`${eq1}${eq2}${eq3+1}${eq4}${eq5}${eq6+1}`);
  const eq4NL=s(`${eq1}${eq2}${eq3}${eq4+1}${eq5}${eq6}`);
  const eq5NL=s(`${eq1}${eq2}${eq3}${eq4}${eq5+1}${eq6}`);

  // ── Build combined max vectors for severity distance computation ──────────
  const getMV=(eq,idx)=>_V4_MAX_VEC[`eq${eq}`][macroKey[eq-1]];
  const eq1M=getMV(1), eq2M=getMV(2);
  const eq3eq6M=(_V4_MAX_VEC.eq3[macroKey[2]]||{})[macroKey[5]]||[];
  const eq4M=getMV(4), eq5M=getMV(5);

  const maxVecs=[];
  for(const a of eq1M) for(const b of eq2M) for(const c of eq3eq6M)
    for(const d of eq4M) for(const e of eq5M) maxVecs.push(a+b+c+d+e);

  // Metric ordinal levels (0 = highest severity)
  const LV={
    AV:{N:0,A:.1,L:.2,P:.3}, PR:{N:0,L:.1,H:.2}, UI:{N:0,P:.1,A:.2},
    AC:{L:0,H:.1}, AT:{N:0,P:.1},
    VC:{H:0,L:.1,N:.2}, VI:{H:0,L:.1,N:.2}, VA:{H:0,L:.1,N:.2},
    SC:{H:.1,L:.2,N:.3}, SI:{S:0,H:.1,L:.2,N:.3}, SA:{S:0,H:.1,L:.2,N:.3},
    CR:{H:0,M:.1,L:.2},  IR:{H:0,M:.1,L:.2},  AR:{H:0,M:.1,L:.2},
  };

  // Extract metric value from a max_vector string (e.g. "AV:N/PR:L/...")
  const extr=(metric,str)=>{
    const i=str.indexOf(metric+':');
    if(i===-1) return null;
    const sub=str.slice(i+metric.length+1);
    const j=sub.indexOf('/');
    return j>0?sub.slice(0,j):sub;
  };

  // Find the max vector that dominates the actual vector (all distances ≥ 0)
  const METRICS=['AV','PR','UI','AC','AT','VC','VI','VA','SC','SI','SA','CR','IR','AR'];
  let dist={};
  for(const mv of maxVecs){
    const d={};
    let ok=true;
    for(const k of METRICS){
      const lv=LV[k]; if(!lv) continue;
      const vm=lv[m(k)]??0, mm=lv[extr(k,mv)]??0;
      d[k]=vm-mm;
      if(d[k]<0){ok=false;break;}
    }
    if(ok){dist=d;break;}
  }

  // Aggregate severity distances per EQ group
  const dEQ1=(dist.AV??0)+(dist.PR??0)+(dist.UI??0);
  const dEQ2=(dist.AC??0)+(dist.AT??0);
  const dEQ3eq6=(dist.VC??0)+(dist.VI??0)+(dist.VA??0)+(dist.CR??0)+(dist.IR??0)+(dist.AR??0);
  const dEQ4=(dist.SC??0)+(dist.SI??0)+(dist.SA??0);
  // EQ5 severity distance is always 0 per FIRST spec

  // ── Mean-distance computation ────────────────────────────────────────────
  const STEP=0.1;
  const mxEQ1 =(_V4_MAX_SEV.eq1[eq1]   ||0)*STEP;
  const mxEQ2 =(_V4_MAX_SEV.eq2[eq2]   ||0)*STEP;
  const mxEQ3eq6=((_V4_MAX_SEV.eq3eq6[eq3]||{})[eq6]||0)*STEP;
  const mxEQ4 =(_V4_MAX_SEV.eq4[eq4]   ||0)*STEP;

  let n=0, meanDist=0;
  const add=(avail,dist,maxSev)=>{
    if(isNaN(avail)) return;
    n++;
    meanDist+=avail*(maxSev>0?dist/maxSev:0);
  };
  add(value-eq1NL,   dEQ1,    mxEQ1);
  add(value-eq2NL,   dEQ2,    mxEQ2);
  add(value-eq3eq6NL,dEQ3eq6, mxEQ3eq6);
  add(value-eq4NL,   dEQ4,    mxEQ4);
  add(value-eq5NL,   0,       1); // EQ5 percent always 0

  if(n>0) value-=meanDist/n;
  return Math.max(0,Math.min(10,Math.round(value*10)/10));
}

function parseCvssVec(str){
  return Object.fromEntries(String(str).replace(/^CVSS:[^/]+\//i,'').split('/').map(p=>p.split(':')));
}

const _reqState={
  CR:'X',IR:'X',AR:'X',                   // security requirements (v2/v3/v4)
  MAV:'X',MAC:'X',MPR:'X',                 // shared modified base (v3+v4)
  MUI:'X',MS:'X',MC:'X',MI:'X',MA:'X',    // v3.x modified base
  MAT:'X',MUI4:'X',                        // v4.0 specific (MAT + v4 MUI)
  MVC:'X',MVI:'X',MVA:'X',                // v4.0 vulnerable system
  MSC:'X',MSI:'X',MSA:'X',               // v4.0 subsequent system
};
function _saveReq(){localStorage.setItem('cat_req',JSON.stringify(_reqState));}
function _loadReq(){try{Object.assign(_reqState,JSON.parse(localStorage.getItem('cat_req')||'{}'));}catch{}}

function _buildNvdEnvUrl(ver, rawVec, state) {
  if (!rawVec) return '#';
  const X=k=>state[k]||'X';
  if (ver==='v3.0'||ver==='v3.1') {
    const v=ver.slice(1);
    const env=`E:X/RL:X/RC:X/CR:${X('CR')}/IR:${X('IR')}/AR:${X('AR')}/MAV:${X('MAV')}/MAC:${X('MAC')}/MPR:${X('MPR')}/MUI:${X('MUI')}/MS:${X('MS')}/MC:${X('MC')}/MI:${X('MI')}/MA:${X('MA')}`;
    return `https://www.first.org/cvss/calculator/${v}#CVSS:${v}/${rawVec}/${env}`;
  }
  if (ver==='v2.0') {
    const nd=x=>x==='X'?'ND':x;
    const env=`CDP:ND/TD:ND/CR:${nd(X('CR'))}/IR:${nd(X('IR'))}/AR:${nd(X('AR'))}`;
    return `https://nvd.nist.gov/vuln-metrics/cvss/v2-calculator?vector=${encodeURIComponent(`${rawVec}/${env}`)}&source=NIST`;
  }
  if (ver==='v4.0') {
    const env=`E:X/CR:${X('CR')}/IR:${X('IR')}/AR:${X('AR')}/MAV:${X('MAV')}/MAC:${X('MAC')}/MAT:${X('MAT')}/MPR:${X('MPR')}/MUI:${X('MUI4')}/MVC:${X('MVC')}/MVI:${X('MVI')}/MVA:${X('MVA')}/MSC:${X('MSC')}/MSI:${X('MSI')}/MSA:${X('MSA')}`;
    return `https://www.first.org/cvss/calculator/4.0#CVSS:4.0/${rawVec}/${env}`;
  }
  return '#';
}

function applyRequirements() {
  const {CR:cr,IR:ir,AR:ar}=_reqState;
  const active=Object.values(_reqState).some(v=>v!=='X');
  document.querySelectorAll('.cvss-badge-wrap').forEach(wrap=>{
    if(!active){wrap.querySelector('.cvss-env-row')?.remove();return;}
    const badge=wrap.querySelector('.cvss-badge');
    const ver=badge?.dataset.cvssVersion;
    if(ver!=='v3.0'&&ver!=='v3.1'&&ver!=='v2.0'&&ver!=='v4.0'){
      wrap.querySelector('.cvss-env-row')?.remove();return;
    }
    const rawVec=badge?.title?.startsWith('Vector: ')?badge.title.slice(8):null;
    if(!rawVec){wrap.querySelector('.cvss-env-row')?.remove();return;}
    const vec=parseCvssVec(rawVec);
    const s=ver==='v2.0'?cvss2ReqScore(vec,_reqState):
          ver==='v4.0'?cvss4ReqScore(vec,_reqState):
          cvss3ReqScore(vec,_reqState);
    if(s===null){wrap.querySelector('.cvss-env-row')?.remove();return;}
    let row=wrap.querySelector('.cvss-env-row');
    let sub;
    if(!row){
      row=document.createElement('div');row.className='cvss-env-row';
      const arr=document.createElement('span');arr.className='cvss-env-arrow';arr.textContent='\u21b3';
      sub=document.createElement('a');sub.className='cvss-env-badge';
      sub.target='_blank';sub.rel='noopener noreferrer';
      row.appendChild(arr);row.appendChild(sub);wrap.appendChild(row);
    } else {sub=row.querySelector('.cvss-env-badge');}
    sub.className=`cvss-env-badge ${cvssColorClass(s)}`;
    sub.textContent=`Env ${ver} ${s.toFixed(1)}`;
    sub.title=`Environmental score — CR:${cr} IR:${ir} AR:${ar}`;
    sub.href=_buildNvdEnvUrl(ver,rawVec,_reqState);
  });
}

// Remplace les 3 const existantes par:
const _REQ_GROUPS=[
  {label:'Security Requirements',items:[
    {id:'CR',l:'Confidentiality Req.',  opts:['X','L','M','H']},
    {id:'IR',l:'Integrity Req.', opts:['X','L','M','H']},
    {id:'AR',l:'Availability Req.', opts:['X','L','M','H']},
  ]},
  {label:'Modified Base — Common (v3+v4)',items:[
    {id:'MAV',l:'Attack Vector',      opts:['X','N','A','L','P']},
    {id:'MAC',l:'Attack Complexity',  opts:['X','L','H']},
    {id:'MPR',l:'Privileges Req.',    opts:['X','N','L','H']},
  ]},
  {label:'Modified Base — v3.x',items:[
    {id:'MUI',l:'User Interaction',   opts:['X','N','R']},
    {id:'MS', l:'Scope',              opts:['X','U','C']},
    {id:'MC', l:'Confidentiality',    opts:['X','N','L','H']},
    {id:'MI', l:'Integrity',          opts:['X','N','L','H']},
    {id:'MA', l:'Availability',       opts:['X','N','L','H']},
  ]},
  {label:'Modified Base — v4.0',items:[
    {id:'MAT', l:'Attack Req.',       opts:['X','N','P']},
    {id:'MUI4',l:'User Interaction',  opts:['X','N','P','A']},
    {id:'MVC', l:'Vuln. Conf.',       opts:['X','H','L','N']},
    {id:'MVI', l:'Vuln. Integ.',      opts:['X','H','L','N']},
    {id:'MVA', l:'Vuln. Avail.',      opts:['X','H','L','N']},
    {id:'MSC', l:'Sub. Conf.',        opts:['X','H','L','N']},
    {id:'MSI', l:'Sub. Integ.',       opts:['X','S','H','L','N']},
    {id:'MSA', l:'Sub. Avail.',       opts:['X','S','H','L','N']},
  ]},
];

/* ── Floating tooltip manager ── */
const _tip = (() => {
  let el = null;
  const ensure = () => {
    if (el) return;
    el = document.createElement('div'); el.id = 'env-tip';
    document.body.appendChild(el);
  };
  return {
    show(text, x, y) { ensure(); el.textContent=text; el.style.left=x+'px'; el.style.top=y+'px'; el.style.opacity='1'; },
    move(x, y)       { if(el){el.style.left=x+'px';el.style.top=y+'px';} },
    hide()           { if(el) el.style.opacity='0'; },
  };
})();

const _M_TIPS = {
  CR: {
    X: 'Not Defined — no effect on the score; base CIA weights are used unchanged.',
    L: 'Low — loss of Confidentiality likely has only a limited adverse effect on the organization (e.g., minor, contained breach).',
    M: 'Medium — loss of Confidentiality likely has a serious adverse effect (e.g., significant data exposure or reputational harm).',
    H: 'High — loss of Confidentiality likely has a catastrophic adverse effect (e.g., regulatory breach, critical data exfiltration).',
  },
  IR: {
    X: 'Not Defined — no effect on the score; base CIA weights are used unchanged.',
    L: 'Low — loss of Integrity likely has only a limited adverse effect on the organization.',
    M: 'Medium — loss of Integrity likely has a serious adverse effect on the organization.',
    H: 'High — loss of Integrity likely has a catastrophic adverse effect (e.g., safety-critical data tampering).',
  },
  AR: {
    X: 'Not Defined — no effect on the score; base CIA weights are used unchanged.',
    L: 'Low — loss of Availability likely has only a limited adverse effect on the organization.',
    M: 'Medium — loss of Availability likely has a serious adverse effect on the organization.',
    H: 'High — loss of Availability likely has a catastrophic adverse effect (e.g., critical system downtime).',
  },
  MAV: {
    X: 'Not Defined — inherits the base Attack Vector value.',
    N: 'Network — the vulnerable component is bound to the network stack and reachable remotely across the Internet. Highest attack reach.',
    A: 'Adjacent — the attack is limited to a logically adjacent network (e.g., same VLAN, Bluetooth, or local subnet).',
    L: 'Local — exploitation requires local access (e.g., logged-in user, local file execution). Not network-reachable.',
    P: 'Physical — the attacker must physically touch or manipulate the hardware. Lowest attack reach.',
  },
  MAC: {
    X: 'Not Defined — inherits the base Attack Complexity value.',
    L: 'Low — no specialized conditions are required; the attacker can exploit the vulnerability reliably and repeatedly without preparation.',
    H: 'High — success depends on conditions beyond the attacker\'s control (e.g., race conditions, specific configurations, prior reconnaissance).',
  },
  MPR: {
    X: 'Not Defined — inherits the base Privileges Required value.',
    N: 'None — no prior authentication or privileges are needed; exploitation is possible as an anonymous or unauthenticated user.',
    L: 'Low — basic user-level privileges are required (e.g., a standard account limited to own files or settings).',
    H: 'High — elevated or administrative privileges with significant control over the vulnerable component are required.',
  },
  MUI: {
    X: 'Not Defined — inherits the base User Interaction value.',
    N: 'None — no user participation is required; the attacker exploits the vulnerability independently.',
    R: 'Required — a user must take a specific action (e.g., click a link, open a file) before exploitation is possible.',
  },
  MS: {
    X: 'Not Defined — inherits the base Scope value.',
    U: 'Unchanged — the exploited vulnerability impacts only the vulnerable component; no other authority or component is affected.',
    C: 'Changed — a successful attack can impact resources managed by a different security authority beyond the vulnerable component.',
  },
  MC: {
    X: 'Not Defined — inherits the base Confidentiality Impact value.',
    N: 'None — no confidentiality impact; no data is disclosed to unauthorized parties.',
    L: 'Low — limited information disclosure; the attacker gains some restricted data but cannot control what is exposed.',
    H: 'High — total loss of confidentiality; the attacker can read all data on the component including credentials and sensitive information.',
  },
  MI: {
    X: 'Not Defined — inherits the base Integrity Impact value.',
    N: 'None — no integrity impact; data cannot be modified by the attacker.',
    L: 'Low — the attacker can modify some data but lacks full control over what is modified or the extent of changes.',
    H: 'High — total loss of integrity; the attacker can modify any data on the component, leading to complete compromise.',
  },
  MA: {
    X: 'Not Defined — inherits the base Availability Impact value.',
    N: 'None — no availability impact; the component remains fully operational.',
    L: 'Low — reduced performance or intermittent outages; the attacker cannot fully deny access but can degrade service.',
    H: 'High — total loss of availability; the attacker can fully deny access to the component causing a complete service outage.',
  },
  MAT: {
    X: 'Not Defined — inherits the base Attack Requirements value (v4.0).',
    N: 'None — a successful attack does not require specific deployment or execution conditions; exploitable in the default state.',
    P: 'Present — exploitation requires specific conditions to be in place (e.g., a particular configuration, software state, or race condition).',
  },
  MUI4: {
    X: 'Not Defined — inherits the base User Interaction value (v4.0).',
    N: 'None — no human interaction is required beyond the attacker; exploitation is fully automated or self-triggered.',
    P: 'Passive — the targeted user interacts with the vulnerable system in the normal course of activity (e.g., browsing a page that silently triggers the exploit).',
    A: 'Active — the targeted user must consciously perform specific actions with the attacker\'s payload (e.g., explicitly open a malicious file or confirm a dialog).',
  },
  MVC: {
    X: 'Not Defined — inherits the base Vulnerable System Confidentiality value (v4.0).',
    H: 'High — total loss of confidentiality on the Vulnerable System; all data including sensitive credentials is exposed.',
    L: 'Low — limited confidentiality loss on the Vulnerable System; partial data disclosure without full attacker control.',
    N: 'None — no confidentiality impact on the Vulnerable System.',
  },
  MVI: {
    X: 'Not Defined — inherits the base Vulnerable System Integrity value (v4.0).',
    H: 'High — total loss of integrity on the Vulnerable System; the attacker can modify any data or code.',
    L: 'Low — limited integrity loss; the attacker can modify some data on the Vulnerable System without full control.',
    N: 'None — no integrity impact on the Vulnerable System.',
  },
  MVA: {
    X: 'Not Defined — inherits the base Vulnerable System Availability value (v4.0).',
    H: 'High — total loss of availability on the Vulnerable System; the component is completely rendered inoperable.',
    L: 'Low — degraded performance on the Vulnerable System; partial denial without complete service loss.',
    N: 'None — no availability impact on the Vulnerable System.',
  },
  MSC: {
    X: 'Not Defined — inherits the base Subsequent System Confidentiality value (v4.0).',
    H: 'High — total loss of confidentiality on the Subsequent System; all data managed by other components or authorities is exposed.',
    L: 'Low — limited confidentiality loss on the Subsequent System; partial data disclosure beyond the vulnerable component.',
    N: 'None — no confidentiality impact on the Subsequent System.',
  },
  MSI: {
    X: 'Not Defined — inherits the base Subsequent System Integrity value (v4.0).',
    S: 'Safety — integrity impacts on the Subsequent System could cause serious physical injury or worse (e.g., industrial control or medical device compromise). Forces score to maximum.',
    H: 'High — total loss of integrity on the Subsequent System; the attacker can arbitrarily modify data across other components.',
    L: 'Low — limited integrity loss on the Subsequent System; partial modification beyond the vulnerable component.',
    N: 'None — no integrity impact on the Subsequent System.',
  },
  MSA: {
    X: 'Not Defined — inherits the base Subsequent System Availability value (v4.0).',
    S: 'Safety — availability impacts could cause serious physical injury or worse (e.g., denial of critical safety systems). Forces score to maximum.',
    H: 'High — total loss of availability on the Subsequent System; other components or systems become fully unreachable.',
    L: 'Low — some availability degradation on the Subsequent System.',
    N: 'None — no availability impact on the Subsequent System.',
  },
};

// Impact severity of each option on the environmental score (blue = X/neutral)
const _CHIP_SEVERITY = {
  CR:  { X:'blue', L:'yellow', M:'orange', H:'red' },
  IR:  { X:'blue', L:'yellow', M:'orange', H:'red' },
  AR:  { X:'blue', L:'yellow', M:'orange', H:'red' },
  MAV: { X:'blue', N:'red', A:'orange', L:'yellow', P:'green' },
  MAC: { X:'blue', L:'red', H:'green' },
  MPR: { X:'blue', N:'red', L:'orange', H:'green' },
  MUI: { X:'blue', N:'red', R:'green' },
  MS:  { X:'blue', U:'orange', C:'red' },
  MC:  { X:'blue', N:'green', L:'orange', H:'red' },
  MI:  { X:'blue', N:'green', L:'orange', H:'red' },
  MA:  { X:'blue', N:'green', L:'orange', H:'red' },
  MAT: { X:'blue', N:'red', P:'green' },
  MUI4:{ X:'blue', N:'red', P:'orange', A:'green' },
  MVC: { X:'blue', H:'red', L:'yellow', N:'green' },
  MVI: { X:'blue', H:'red', L:'yellow', N:'green' },
  MVA: { X:'blue', H:'red', L:'yellow', N:'green' },
  MSC: { X:'blue', H:'red', L:'yellow', N:'green' },
  MSI: { X:'blue', S:'red', H:'orange', L:'yellow', N:'green' },
  MSA: { X:'blue', S:'red', H:'orange', L:'yellow', N:'green' },
};

const _METRIC_DESC = {
  CR:   'Confidentiality Requirement — customizes the score based on the relative importance of confidentiality to your organization.',
  IR:   'Integrity Requirement — customizes the score based on the relative importance of integrity to your organization.',
  AR:   'Availability Requirement — customizes the score based on the relative importance of availability to your organization.',
  MAV:  'Modified Attack Vector — overrides the base AV. Reflects the context by which exploitation is possible; the more remote the attacker, the higher the score.',
  MAC:  'Modified Attack Complexity — overrides the base AC. Describes conditions beyond the attacker\'s control that must exist to exploit the vulnerability.',
  MPR:  'Modified Privileges Required — overrides the base PR. Describes the privilege level an attacker must possess before successfully exploiting the vulnerability.',
  MUI:  'Modified User Interaction (v3.x) — overrides the base UI. Captures whether a human user other than the attacker must participate in the compromise.',
  MS:   'Modified Scope (v3.x) — overrides the base S. Indicates whether a successful attack can impact components beyond the vulnerable component.',
  MC:   'Modified Confidentiality Impact (v3.x) — overrides the base C. Measures the impact on confidentiality of the vulnerable component.',
  MI:   'Modified Integrity Impact (v3.x) — overrides the base I. Measures the impact on trustworthiness and veracity of information.',
  MA:   'Modified Availability Impact (v3.x) — overrides the base A. Measures the impact on the availability of the vulnerable component.',
  MAT:  'Modified Attack Requirements (v4.0) — overrides the base AT. Captures prerequisite deployment and execution conditions that enable the attack.',
  MUI4: 'Modified User Interaction (v4.0) — overrides the base UI (v4 scale). Captures whether a human user must participate in the compromise.',
  MVC:  'Modified Vulnerable System Confidentiality (v4.0) — overrides the base VC. Measures confidentiality impact on the vulnerable system.',
  MVI:  'Modified Vulnerable System Integrity (v4.0) — overrides the base VI. Measures integrity impact on the vulnerable system.',
  MVA:  'Modified Vulnerable System Availability (v4.0) — overrides the base VA. Measures availability impact on the vulnerable system.',
  MSC:  'Modified Subsequent System Confidentiality (v4.0) — overrides the base SC. Measures confidentiality impact on systems beyond the vulnerable component.',
  MSI:  'Modified Subsequent System Integrity (v4.0) — overrides the base SI. Safety override (S) forces the score to 10. Measures integrity impact on subsequent systems.',
  MSA:  'Modified Subsequent System Availability (v4.0) — overrides the base SA. Safety override (S) forces the score to 10. Measures availability impact on subsequent systems.',
};

function _attachMetricTip(el, id) {
  const desc = _METRIC_DESC[id]; if (!desc) return;
  el.style.cursor = 'help';
  el.addEventListener('mouseenter', e => _tip.show(desc, e.clientX + 14, e.clientY - 48));
  el.addEventListener('mousemove',  e => _tip.move(e.clientX + 14, e.clientY - 48));
  el.addEventListener('mouseleave', () => _tip.hide());
}

/* ── Shared chip factory (panel + modal, synced via data-id/data-opt) ── */
function _buildReqChips(id, opts) {
  const wrap = document.createElement('div'); wrap.className = 'req-chips';
  opts.forEach(opt => {
    const sev = _CHIP_SEVERITY[id]?.[opt];
    const sevCls = (sev && sev !== 'blue') ? ` sev-${sev}` : '';
    const c = document.createElement('button'); c.type = 'button';
    c.className = `req-chip${sevCls}${_reqState[id] === opt ? ' on' : ''}`;
    c.textContent = opt; c.dataset.id = id; c.dataset.opt = opt;
    const tip = _M_TIPS[id]?.[opt];
    if (tip) {
      c.addEventListener('mouseenter', e => _tip.show(tip, e.clientX+14, e.clientY-48));
      c.addEventListener('mousemove',  e => _tip.move(e.clientX+14, e.clientY-48));
      c.addEventListener('mouseleave', () => _tip.hide());
    }
    c.addEventListener('click', () => {
      _reqState[id] = opt;
      document.querySelectorAll(`.req-chip[data-id="${id}"]`)
        .forEach(x => x.classList.toggle('on', x.dataset.opt === opt));
      _saveReq(); applyRequirements();
    });
    wrap.appendChild(c);
  });
  return wrap;
}

/* ── Compact panel: CR/IR/AR + button ── */
function initReqMetrics() {
  const grid = document.getElementById('reqMetricsGrid'); if (!grid) return;
  grid.innerHTML = '';
  _REQ_GROUPS[0].items.forEach(({id, l, opts}) => {
    const row = document.createElement('div'); row.className = 'req-metric-row';
    const lbl = document.createElement('span'); lbl.className = 'req-metric-label'; lbl.textContent = l;
    _attachMetricTip(lbl, id);
    row.appendChild(lbl); row.appendChild(_buildReqChips(id, opts)); grid.appendChild(row);
  });
  const calcBtn = document.createElement('button');
  calcBtn.type = 'button'; calcBtn.className = 'req-calc-btn';
  calcBtn.textContent = '🧮 Modified base metrics…';
  calcBtn.addEventListener('click', openEnvCalc);
  grid.appendChild(calcBtn);
  const rst = document.createElement('button'); rst.type = 'button'; rst.className = 'req-reset-btn';
  rst.textContent = '↺ Reset all metrics';
  rst.addEventListener('click', resetEnvCalc);
  grid.appendChild(rst);
}

/* ── Modal builder ── */
function _buildEnvCalcContent(container) {
  container.innerHTML = '';
  _REQ_GROUPS.forEach(({label, items}) => {
    const gl = document.createElement('div'); gl.className = 'req-group-label'; gl.textContent = label;
    container.appendChild(gl);
    items.forEach(({id, l, opts}) => {
      const row = document.createElement('div'); row.className = 'req-metric-row';
      const lbl = document.createElement('span'); lbl.className = 'req-metric-label'; lbl.textContent = l;
      _attachMetricTip(lbl, id);
      row.appendChild(lbl); row.appendChild(_buildReqChips(id, opts)); container.appendChild(row);
    });
  });
}

function openEnvCalc() {
  const modal = document.getElementById('envCalcModal'); if (!modal) return;
  _buildEnvCalcContent(document.getElementById('envCalcContent'));
  modal.hidden = false; document.body.style.overflow = 'hidden';
}
function closeEnvCalc() {
  const modal = document.getElementById('envCalcModal'); if (!modal) return;
  modal.hidden = true; document.body.style.overflow = ''; _tip.hide();
}
function resetEnvCalc() {
  Object.keys(_reqState).forEach(k => _reqState[k] = 'X');
  _saveReq(); applyRequirements();
  document.querySelectorAll('.req-chip[data-opt]').forEach(c => c.classList.toggle('on', c.dataset.opt === 'X'));
}

/* =================================================================
   SOURCE FILTER
   ================================================================= */
const SOURCE_GROUPS = {
  databases: ["CVEList","NVD","ENISA","CISA"],
  editors:   ["RedHat","SUSE","Debian","Ubuntu","Microsoft","Amazon","LibreOffice","PostgreSQL","Oracle","Xen"],
};
const ALL_SOURCES   = [...SOURCE_GROUPS.databases, ...SOURCE_GROUPS.editors];
const activeSources  = new Set(ALL_SOURCES);

function applyFilter() {
  const _n = s => ALL_SOURCES.includes(s) ? s : "CVEList"; // unknown → CVEList family
  document.querySelectorAll(".desc-row[data-sources]").forEach(row => {
    const srcs = row.dataset.sources.split(",");
    const vis  = srcs.filter(s => activeSources.has(_n(s)));
    row.style.display = vis.length ? "" : "none";
    row.querySelectorAll(".source-badge").forEach(b => {
      const n = b.textContent.trim();
      b.style.display = (!n || n === "?" || activeSources.has(n)) ? "" : "none";
    });
  });
  document.querySelectorAll(".cvss-badge[data-sources]").forEach(badge => {
    const srcs = badge.dataset.sources.split(",");
    const vis  = srcs.filter(s => activeSources.has(_n(s)));
    badge.style.display = vis.length ? "" : "none";
    const span = badge.querySelector(".sources"); if (span) span.textContent = vis.join(", ");
    const wrap = badge.closest(".cvss-badge-wrap");
    if (wrap) wrap.style.display = badge.style.display;
  });
  document.querySelectorAll(".ref-row[data-sources]").forEach(row => {
    const srcs = row.dataset.sources.split(",");
    const vis  = srcs.some(s => activeSources.has(_n(s)));
    row.style.display = vis ? "" : "none";
    row.querySelectorAll(".source-badge").forEach(b => {
      const n = b.textContent.trim();
      b.style.display = (!n || activeSources.has(n)) ? "" : "none";
    });
  });
  document.querySelectorAll(".cwe-entry").forEach(entry => {
    const chip = entry.querySelector(".cwe-chip[data-sources]"); if (!chip) return;
    const srcs = chip.dataset.sources.split(",");
    const vis  = srcs.filter(s => activeSources.has(_n(s)));
    entry.style.display = vis.length ? "" : "none";
    const srEl = chip.querySelector(".cwe-chip-srcs"); if (srEl) srEl.textContent = vis.length ? ` (${vis.join(", ")})` : "";
  });
  // Source chips — consider both filter state and collapse state
  document.querySelectorAll(".source-chip[data-source]").forEach(chip => {
    const src    = chip.dataset.source;
    const active = activeSources.has(_n(src));
    chip.dataset.filtered = active ? "false" : "true";
    const collapsed = chip.dataset.collapsed === "true";
    const expanded  = chip.closest(".card-chips-right")?.classList.contains("chips-expanded");
    chip.style.display = (!active || (collapsed && !expanded)) ? "none" : "";
  });
}

/* Collapse non-ok source chips behind a "+N ▾" toggle button */
function rebuildChipVisibility(cve) {
  const chipsRight = document.querySelector(`.cve-card[data-cve="${cve}"] .card-chips-right`);
  if (!chipsRight) return;
  const expanded = chipsRight.classList.contains("chips-expanded");
  let collapsedCount = 0;
  chipsRight.querySelectorAll(".source-chip").forEach(chip => {
    const dot = chip.querySelector(".dot");
    const cls = dot ? Array.from(dot.classList).find(c => c.startsWith("dot-") && c !== "dot") : null;
    const settled = cls && cls !== "dot-wait" && cls !== "dot-unknown";
    const collapse = settled && cls !== "dot-ok";
    chip.dataset.collapsed = collapse ? "true" : "false";
    if (collapse) collapsedCount++;
    const filtered = chip.dataset.filtered === "true";
    chip.style.display = (filtered || (collapse && !expanded)) ? "none" : "";
  });
  let moreBtn = chipsRight.querySelector(".chips-more");
  if (collapsedCount === 0) { moreBtn?.remove(); return; }
  if (!moreBtn) {
    moreBtn = document.createElement("button");
    moreBtn.className = "chips-more"; moreBtn.type = "button";
    moreBtn.addEventListener("click", e => {
      e.stopPropagation();
      chipsRight.classList.toggle("chips-expanded");
      rebuildChipVisibility(cve);
    });
    chipsRight.appendChild(moreBtn);
  }
  moreBtn.textContent = expanded ? "▴" : `+${collapsedCount} ▾`;
}

function toggleOptionsPanel() {
  const panel = document.getElementById("optionsPanel");
  const btn   = document.getElementById("optionsBtn");
  panel.classList.toggle("open");
  btn.classList.toggle("active", panel.classList.contains("open"));
}
document.addEventListener("click", e => {
  const panel = document.getElementById("optionsPanel");
  const btn   = document.getElementById("optionsBtn");
  if (panel && !panel.contains(e.target) && btn && !btn.contains(e.target)) {
    panel.classList.remove("open"); btn.classList.remove("active");
  }
});
/* =================================================================
   FIELD VISIBILITY
   ================================================================= */
const FIELD_CONFIG = [
  { key: "desc",  label: "Description", bodyClass: "hide-field-desc"  },
  { key: "cvss3", label: "CVSS v3",     bodyClass: "hide-field-cvss3" },
  { key: "cvss4", label: "CVSS v4",     bodyClass: "hide-field-cvss4" },
  { key: "cvss2", label: "CVSS v2",     bodyClass: "hide-field-cvss2" },
  { key: "cwe",   label: "CWE",         bodyClass: "hide-field-cwe"   },
  { key: "refs",  label: "References",  bodyClass: "hide-field-refs"  },
];
// true = visible, false = hidden
const fieldVisible = Object.fromEntries(FIELD_CONFIG.map(f => [f.key, true]));

function _saveFieldState() {
  localStorage.setItem("cat_fields", JSON.stringify(fieldVisible));
}
function applyFieldFilter() {
  FIELD_CONFIG.forEach(({ key, bodyClass }) => {
    document.body.classList.toggle(bodyClass, !fieldVisible[key]);
  });
  // Recalculate cvssMax for each card regarding the visibles sources
  document.querySelectorAll(".cve-card:not(.template)").forEach(card => {
    const badges = Array.from(card.querySelectorAll(".cvss-badge[data-cvss-version]"));
    const scores = badges
      .filter(b => {
        const v = b.dataset.cvssVersion;
        if (v === "v4.0") return fieldVisible.cvss4 !== false;
        if (v === "v3.0" || v === "v3.1") return fieldVisible.cvss3 !== false;
        if (v === "v2.0") return fieldVisible.cvss2 !== false;
        return true;
      })
      .map(b => parseFloat(b.querySelector(".score")?.textContent ?? "-1"))
      .filter(s => !isNaN(s));
    card.dataset.cvssMax = scores.length ? String(Math.max(...scores)) : "-1";
  });
  if (_currentSort === "cvss-desc" || _currentSort === "cvss-asc") applySort();
  else refreshSummary();
}
function initFieldChips() {
  const container = document.getElementById("fieldChips"); if (!container) return;
  // Rstore from localStorage
  try {
    const saved = JSON.parse(localStorage.getItem("cat_fields") || "{}");
    FIELD_CONFIG.forEach(({ key }) => {
      if (key in saved) fieldVisible[key] = saved[key];
    });
  } catch {}
  applyFieldFilter();
  FIELD_CONFIG.forEach(({ key, label }) => {
    const chip = document.createElement("span");
    chip.className = "filter-chip" + (fieldVisible[key] ? " on" : "");
    chip.dataset.field = key;
    const dot = document.createElement("span"); dot.className = "fc-dot";
    chip.appendChild(dot);
    chip.appendChild(document.createTextNode(label));
    chip.addEventListener("click", () => {
      fieldVisible[key] = !fieldVisible[key];
      chip.classList.toggle("on", fieldVisible[key]);
      applyFieldFilter();
      _saveFieldState();
    });
    container.appendChild(chip);
  });
}


function _saveFilterState() {
  localStorage.setItem("cat_filters", JSON.stringify([...activeSources]));
}
function initFilterChips() {
  const dbContainer = document.getElementById("filterChipsDatabases");
  const edContainer = document.getElementById("filterChipsEditors");
  if (!dbContainer || !edContainer) return;
  try {
    const saved = localStorage.getItem("cat_filters");
    if (saved) {
      const savedArr = JSON.parse(saved);
      activeSources.clear();
      savedArr.forEach(s => { if (ALL_SOURCES.includes(s)) activeSources.add(s); });
    }
  } catch {}

  function renderChip(src, container) {
    const chip = document.createElement("span");
    chip.className = "filter-chip" + (activeSources.has(src) ? " on" : "");
    chip.dataset.src = src;
    const dot = document.createElement("span"); dot.className = "fc-dot";
    chip.appendChild(dot); chip.appendChild(document.createTextNode(src));
    chip.addEventListener("click", () => {
      if (activeSources.has(src)) { activeSources.delete(src); chip.classList.remove("on"); }
      else { activeSources.add(src); chip.classList.add("on"); }
      _saveFilterState();
      applyFilter();
    });
    container.appendChild(chip);
  }

  SOURCE_GROUPS.databases.forEach(src => renderChip(src, dbContainer));
  SOURCE_GROUPS.editors.forEach(src => renderChip(src, edContainer));
}

/* =================================================================
   CVE SUMMARY PANEL
   ================================================================= */
function refreshSummary() {
  const panel   = document.getElementById("cveSummary");
  const list    = document.getElementById("summaryList");
  const countEl = document.getElementById("summaryCount");
  if (!panel || !list || !countEl) return;

  const cards = Array.from(document.querySelectorAll(".cve-card:not(.template)"));
  countEl.textContent = cards.length;

  if (!cards.length) {
    panel.classList.remove("visible");
    panel.classList.remove("open");
    return;
  }
  panel.classList.add("visible");

  list.innerHTML = "";
  cards.forEach(card => {
    const cve = card.dataset.cve; if (!cve) return;
    const cvssMax = parseFloat(card.dataset.cvssMax ?? "-1");
    const dotClass = cvssMax < 0 ? "sdot-none" : cvssMax < 4 ? "sdot-low"
      : cvssMax < 7 ? "sdot-medium" : cvssMax < 9 ? "sdot-high" : "sdot-critical";

    const item = document.createElement("button");
    item.className = "summary-item"; item.type = "button"; item.title = `Scroll to ${cve}`;
    const dot = document.createElement("span"); dot.className = "summary-dot " + dotClass;
    const label = document.createElement("span"); label.className = "summary-label"; label.textContent = cve;

    // Copy button
    const copyBtn = document.createElement("button");
    copyBtn.className = "summary-copy"; copyBtn.type = "button"; copyBtn.title = `Copy ${cve}`;
    copyBtn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>`;
    copyBtn.addEventListener("click", e => {
      e.stopPropagation(); 
      navigator.clipboard.writeText(cve).then(() => {
        copyBtn.classList.add("copied");
        copyBtn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>`;
        setTimeout(() => {
          copyBtn.classList.remove("copied");
          copyBtn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>`;
        }, 1500);
      }).catch(() => {
        // Fallback if clipboard API unreachable
        const ta = document.createElement("textarea");
        ta.value = cve; ta.style.position = "fixed"; ta.style.opacity = "0";
        document.body.appendChild(ta); ta.select();
        document.execCommand("copy"); document.body.removeChild(ta);
        copyBtn.classList.add("copied");
        setTimeout(() => copyBtn.classList.remove("copied"), 1500);
      });
    });

    item.appendChild(dot); item.appendChild(label); item.appendChild(copyBtn);
    item.addEventListener("click", () => {
      panel.classList.remove("open");
      const headerH = document.querySelector(".header")?.offsetHeight ?? 0;
      const cardTop = card.getBoundingClientRect().top + window.scrollY - headerH - 8;
      window.scrollTo({ top: cardTop, behavior: "smooth" });
      card.classList.add("summary-highlight");
      setTimeout(() => card.classList.remove("summary-highlight"), 1100);
    });
    list.appendChild(item);
  });
}

function toggleSummary() {
  const panel = document.getElementById("cveSummary"); if (!panel) return;
  panel.classList.toggle("open");
}

// Close the dropdown if click out
document.addEventListener("click", e => {
  const panel = document.getElementById("cveSummary");
  if (panel && panel.classList.contains("open") && !panel.contains(e.target))
    panel.classList.remove("open");
});

/* =================================================================
   SEARCH
   ================================================================= */
async function handleSearch() {
  const btn = document.getElementById("searchBtn"), input = document.getElementById("searchInput");
  const raw = input.value.trim(); if (!raw) return;
  const newCves = extractCveIds(raw).filter(c => !displayedCVEs.has(c));
  if (!newCves.length) { alert("All these CVEs are already displayed."); return; }
  retractCurtain();
  getXenJson();                                         // pre-warm Xen advisory index
  if (newCves.length > 1) prefetchEpssBatch(newCves);  // batch EPSS for multi-CVE search
  btn.disabled = true; btn.textContent = `Loading (0/${newCves.length})…`;
  for (let i = 0; i < newCves.length; i++) {
    const cve = newCves[i]; displayedCVEs.add(cve);
    btn.textContent = `Loading (${i+1}/${newCves.length})…`;
    await renderCve(cve); if (i < newCves.length - 1) await wait(DELAY_MS);
  }
  btn.disabled = false; btn.textContent = "Search";
}

/* =================================================================
   INIT
   ================================================================= */
document.addEventListener("DOMContentLoaded", () => {
  const input = document.getElementById("searchInput"), btn = document.getElementById("searchBtn");
  input.addEventListener("input", () => { btn.disabled = !extractCveIds(input.value.toUpperCase()).length; });
  initFilterChips();
  initFieldChips();
  _loadReq();
  initReqMetrics();
  initLanding(); // init landing curtain data feeds
  document.addEventListener('keydown', e => { if (e.key === 'Escape') closeEnvCalc(); });

  // Restore the sort from localStorage
  const savedSort = localStorage.getItem("cat_sort");
  if (savedSort) {
    _currentSort = savedSort;
    const sortSel = document.getElementById("sortSelect");
    if (sortSel) sortSel.value = savedSort;
  }

  // Parse ?cves= from URL and queue them for loading
  const urlCves = extractCveIds(new URLSearchParams(location.search).get("cves") || "");
  if (urlCves.length) {
    // Clean the URL without reloading the page
    history.replaceState(null, "", location.pathname);
    retractCurtain();
    (async () => {
      for (let i = 0; i < urlCves.length; i++) {
        const cve = urlCves[i];
        if (displayedCVEs.has(cve)) continue;
        displayedCVEs.add(cve);
        await renderCve(cve);
        if (i < urlCves.length - 1) await wait(DELAY_MS);
      }
      updateClearSection(); refreshSummary();
      if (_currentSort !== "none") applySort();
    })();
    return; // skip the localStorage restore to avoid duplicate cards on first load
  }

  const saved = storageGetCves();
  if (saved.length) {
    retractCurtain();
    (async () => {
      for (let i = 0; i < saved.length; i++) {
        const cve = saved[i];
        if (displayedCVEs.has(cve)) continue;
        displayedCVEs.add(cve);
        const cached = sessionLoad(cve);
        await renderCve(cve, { skipStorage: true, cachedData: cached });
        if (!cached && i < saved.length - 1) await wait(DELAY_MS);
      }
      updateClearSection();
      refreshSummary();
      if (_currentSort !== "none") applySort();
    })();
  }
});


/* =================================================================
   CARD ACTIONS — delete / clear / refresh
   ================================================================= */
function updateClearSection() {
  const section = document.getElementById("clearSection"); if (!section) return;
  section.style.display = document.querySelectorAll(".cve-card:not(.template)").length ? "" : "none";
}

function deleteCve(cve) {
  document.querySelector(`.cve-card[data-cve="${cve}"]`)?.remove();
  displayedCVEs.delete(cve); cveData.delete(cve); storageRemoveCve(cve); sessionRemove(cve);
  
  updateClearSection(); refreshSummary();
  if (!document.querySelectorAll(".cve-card:not(.template)").length) expandCurtain();
}

function clearAllCves() {
  document.querySelectorAll(".cve-card:not(.template)").forEach(c => c.remove());
  displayedCVEs.clear(); cveData.clear();
  storageClearCves(); sessionClearAll();
  updateClearSection(); refreshSummary();
  expandCurtain();
}

async function refreshCve(cve) {
  const stored = cveData.get(cve); if (!stored) return;
  const { ctx } = stored;

  // Phase 2 failed sources
  const toRefresh = SOURCE_CONFIG.map(s => s.name).filter(name => {
    const dot = document.querySelector(`#dot-${name}-${cve} .dot`);
    return dot && (dot.classList.contains("dot-fail") || dot.classList.contains("dot-networkerror"));
  });

  // CVEList : silent retry if not already charged
  const retrysCveList = !ctx.cveListData;

  if (!toRefresh.length && !retrysCveList) return;

  const card = document.querySelector(`.cve-card[data-cve="${cve}"]`);
  const btn = card?.querySelector(".card-refresh-btn");
  if (btn) btn.classList.add("spinning");
  stored.refsSpinnerEl.style.display = "";

  const tasks = toRefresh.map(name => runSourceFetch(name, cve, stored));

  if (retrysCveList) tasks.push((async () => {
    const data = await fetchCveListData(cve);
    if (!data) return;
    ctx.cveListData = data;
    // Updating header if "not in CVEList"
    const cardEl = document.querySelector(`.cve-card[data-cve="${cve}"]`);
    if (cardEl) {
      cardEl.classList.remove("no-cvelist");
      const lbl = cardEl.querySelector(".no-cvelist-label");
      if (lbl) lbl.remove();
      // Updating assigner + date
      const cna2 = data.containers?.cna;
      const assigner = data.cveMetadata?.assignerShortName;
      const published = data.cveMetadata?.datePublished;
      const assignerEl = cardEl.querySelector(".assigner");
      if (assignerEl && assigner) {
        assignerEl.textContent = assigner;
        assignerEl.href = `https://www.cve.org/CVERecord?id=${cve}`;
        assignerEl.classList.remove("unknown");
      }
      const dateEl = cardEl.querySelector(".date");
      if (dateEl && published) {
        dateEl.textContent = new Date(published).toLocaleDateString("en-GB");
        cardEl.dataset.date = published;
      }
      // Add CVElist scores (CNA + ADP)
      const cnaSource2 = normalizeText(data?.containers?.cna?.providerMetadata?.shortName) || "CVEList";
      extractMetricsFromContainer(cna2, cnaSource2, stored.cvssBase);
      getAdpContainers(data).forEach(adp => extractMetricsFromContainer(adp, "CISA-ADP", stored.cvssBase));
      sortCvss(stored.cvssBase);
    }
    stored.refreshCard();
    stored.refreshCwe();
  })());

  await Promise.allSettled(tasks);
  if (btn) btn.classList.remove("spinning");
  stored.refsSpinnerEl.style.display = "none";
  sessionSave(cve, ctx, stored.cvssBase);
}

async function runSourceFetch(srcName, cve, stored) {
  const { ctx, cvssBase, setDot, refreshCard, refreshCwe, excludedUrls } = stored;
  try {
    switch (srcName) {
      case "NVD": {
        setDot("NVD","wait");
        const r = await fetchNvdData(cve); ctx.nvdData = r?.data||null; ctx.nvdResult = r;
        if (ctx.nvdData?.metrics) { const m=ctx.nvdData.metrics;
          (m.cvssMetricV40||[]).forEach(s=>pushCvss(cvssBase,"v4.0",s.cvssData,"NVD"));
          (m.cvssMetricV31||[]).forEach(s=>pushCvss(cvssBase,"v3.1",s.cvssData,"NVD"));
          (m.cvssMetricV30||[]).forEach(s=>pushCvss(cvssBase,"v3.0",s.cvssData,"NVD"));
          (m.cvssMetricV2 ||[]).forEach(s=>pushCvss(cvssBase,"v2.0",s.cvssData,"NVD")); sortCvss(cvssBase); }
        refreshCard(); setDot("NVD", r?.networkError?"networkerror":r?.data?"ok":"fail"); break;
      }
      case "RedHat": {
        setDot("RedHat","wait");
        const [rhOld,rhCsaf] = await Promise.all([fetchRedHatData(cve),fetchRedHatCsaf(cve)]);
        ctx.rhOld=rhOld??null; ctx.rhCsaf=rhCsaf??null; refreshCard();
        const vuln = ctx.rhCsaf?.document?.vulnerabilities?.[0]||ctx.rhCsaf?.vulnerabilities?.[0];
        if (vuln?.product_status) { const ps=vuln.product_status;
          const aff=(ps.known_affected||[]).length+(ps.fixed||[]).length+(ps.under_investigation||[]).length;
          setDot("RedHat", aff>0?"ok":(ps.known_not_affected||[]).length>0?"notaffected":"ok");
        } else if (ctx.rhOld) {
          const hasScore=!!(ctx.rhOld.cvss?.cvss_base_score||ctx.rhOld.cvss3?.cvss3_base_score);
          if (hasScore||!!ctx.rhOld.threat_severity) setDot("RedHat","ok");
          else if (/does not affect/i.test(ctx.rhOld.statement||"")) setDot("RedHat","notaffected");
          else if (ctx.rhOld.bugzilla) setDot("RedHat","ok"); else setDot("RedHat","notaffected");
        } else {
          const r=await proxyFetchWithStatus(`https://access.redhat.com/security/cve/${encodeURIComponent(cve)}`,"text");
          if (r.httpStatus===0) setDot("RedHat","networkerror");
          else if (!r.data||r.httpStatus===404) setDot("RedHat","fail");
          else if (/does not affect red hat/i.test(r.data)) setDot("RedHat","notaffected");
          else if (/threat_severity|affected_release|cve-severity|bugzilla\.redhat\.com/i.test(r.data)) setDot("RedHat","ok");
          else setDot("RedHat","fail");
        }
        refreshCwe(); break;
      }
      case "SUSE": {
        setDot("SUSE","wait");
        const r = await fetchSuseCsaf(cve);
        ctx.suseCsaf = r?.data ?? null;
        refreshCard();
        if (r?.networkError) setDot("SUSE","networkerror");
        else if (ctx.suseCsaf) setDot("SUSE","ok");
        else {
          // CSAF missing → check the existance of the SUSE page
          const pageStatus = await checkUrl(SOURCE_CONFIG.find(sc=>sc.name==="SUSE").url(cve));
          // "ok" -> page exist and description available
          setDot("SUSE", pageStatus === "ok" ? "notaffected" : pageStatus);
        }
        refreshCwe(); break;
      }
      case "Debian": {
        setDot("Debian","wait"); const d=await fetchDebianDescription(cve); ctx.debianData=d??null; refreshCard();
        if (ctx.debianData?.networkError) setDot("Debian","networkerror");
        else if (!ctx.debianData) setDot("Debian","fail");
        else if (ctx.debianData.notAffected===true) setDot("Debian","notaffected");
        else if (ctx.debianData.desc||ctx.debianData.notAffected===false) setDot("Debian","ok");
        else setDot("Debian","fail"); break;
      }
      case "Ubuntu": {
        setDot("Ubuntu","wait"); const d=await fetchUbuntuData(cve); ctx.ubuntuData=d??null; refreshCard();
        if (ctx.ubuntuData?.networkError) setDot("Ubuntu","networkerror");
        else if (ctx.ubuntuData?.notAffected===false) setDot("Ubuntu","ok");
        else if (ctx.ubuntuData?.notAffected===true) setDot("Ubuntu","notaffected");
        else setDot("Ubuntu","fail"); break;
      }
      case "Microsoft": {
        setDot("Microsoft","wait"); const d=await fetchMsrcData(cve); ctx.msrcData=d??null; refreshCard();
        setDot("Microsoft",ctx.msrcData?.dotStatus||"fail",ctx.msrcData?.dotUrl); refreshCwe(); break;
      }
      case "Amazon": {
        setDot("Amazon","wait"); const d=await fetchAmazonData(cve); ctx.amazonData=d??null; refreshCard();
        if (ctx.amazonData?.networkError) setDot("Amazon","networkerror");
        else if (!ctx.amazonData?.pageFound) setDot("Amazon","fail");
        else if (ctx.amazonData?.desc||ctx.amazonData?.cvssList?.length) setDot("Amazon","ok");
        else setDot("Amazon","notaffected"); break;
      }
      case "LibreOffice": {
        setDot("LibreOffice","wait"); const d=await fetchLibreOfficeData(cve); ctx.libreofficeData=d??null; refreshCard();
        if (ctx.libreofficeData?.networkError) setDot("LibreOffice","networkerror");
        else if (!ctx.libreofficeData?.pageFound) setDot("LibreOffice","fail");
        else if (ctx.libreofficeData?.desc) setDot("LibreOffice","ok");
        else setDot("LibreOffice","notaffected"); break;
      }
      case "PostgreSQL": {
        setDot("PostgreSQL","wait"); const d=await fetchPostgreSQLData(cve); ctx.postgresData=d??null; refreshCard();
        if (ctx.postgresData?.networkError) setDot("PostgreSQL","networkerror");
        else if (!ctx.postgresData?.pageFound) setDot("PostgreSQL","fail");
        else if (ctx.postgresData?.desc||ctx.postgresData?.cvssList?.length) setDot("PostgreSQL","ok");
        else setDot("PostgreSQL","notaffected"); break;
      }
      case "Oracle": {
        setDot("Oracle","wait"); const d=await fetchOracleData(cve); ctx.oracleData=d??null; refreshCard();
        if (ctx.oracleData?.networkError) setDot("Oracle","networkerror");
        else if (!ctx.oracleData?.pageFound) setDot("Oracle","fail");
        else if (ctx.oracleData?.desc||ctx.oracleData?.cvssList?.length) setDot("Oracle","ok");
        else setDot("Oracle","notaffected"); break;
      }
      case "Xen": {
        setDot("Xen","wait"); const d=await fetchXenData(cve); ctx.xenData=d??null;
        if (ctx.xenData?.advisoryUrl) excludedUrls.add(ctx.xenData.advisoryUrl);
        refreshCard();
        if (ctx.xenData?.networkError) setDot("Xen","networkerror");
        else if (ctx.xenData?.cveFound) setDot("Xen","ok",ctx.xenData.advisoryUrl);
        else setDot("Xen","fail"); break;
      }
      case "CISA": {
        setDot("CISA","wait"); const d=await fetchCisaData(cve); ctx.cisaData=d??null; refreshCard(); refreshCwe();
        if (ctx.cisaData?.networkError) setDot("CISA","networkerror");
        else if (ctx.cisaData?.pageFound) setDot("CISA","ok");
        else setDot("CISA","fail"); break;
      }
      case "ENISA": {
        setDot("ENISA","wait"); const d=await fetchEnisaData(cve); ctx.enisaData=d??null;
        if (ctx.enisaData?.euvdPageUrl) excludedUrls.add(ctx.enisaData.euvdPageUrl);
        refreshCard();
        if (ctx.enisaData?.networkError)   setDot("ENISA","networkerror");
        else if (ctx.enisaData?.pageFound) setDot("ENISA","ok",ctx.enisaData.euvdPageUrl);
        else                               setDot("ENISA","fail"); break;
      }
    }
  } catch { setDot(srcName,"networkerror"); }
}

/* =================================================================
   SORT
   ================================================================= */
let _currentSort = "none";

function setSort(val) { _currentSort = val; localStorage.setItem("cat_sort", val); applySort(); }

let _sortDebounceTimer = null;

/** Sort the highest score among CVSS version visibles */
function computeVisibleCvssMax(cvssAll) {
  const versionAllowed = v => {
    if (v === "v4.0") return fieldVisible.cvss4 !== false;
    if (v === "v3.0" || v === "v3.1") return fieldVisible.cvss3 !== false;
    if (v === "v2.0") return fieldVisible.cvss2 !== false;
    return true;
  };
  const visible = cvssAll.filter(e => versionAllowed(e.version));
  return visible.length ? visible[0].score : -1; // cvssAll déjà trié desc
}

function applySortIfActive() {
  if (_currentSort === "none") { refreshSummary(); return; }
  clearTimeout(_sortDebounceTimer);
  _sortDebounceTimer = setTimeout(applySort, 120);
}

function applySort() {
  const container = document.getElementById("cveResults");
  const cards = Array.from(container.querySelectorAll(".cve-card:not(.template)"));
  if (!cards.length) return;
  cards.sort((a, b) => {
    switch (_currentSort) {
      case "cvss-desc": return parseFloat(b.dataset.cvssMax??"-1") - parseFloat(a.dataset.cvssMax??"-1");
      case "cvss-asc": {
        const sa=parseFloat(a.dataset.cvssMax??"-1"), sb=parseFloat(b.dataset.cvssMax??"-1");
        if (sa===-1&&sb===-1) return 0; if (sa===-1) return 1; if (sb===-1) return -1; return sa-sb;
      }
      case "date-desc": return (b.dataset.date||"").localeCompare(a.dataset.date||"");
      case "date-asc":  return (a.dataset.date||"").localeCompare(b.dataset.date||"");
      case "id-asc":  return (a.dataset.id||"").localeCompare(b.dataset.id||"");
      case "id-desc": return (b.dataset.id||"").localeCompare(a.dataset.id||"");
      default: return 0;
    }
  });
  cards.forEach(c => container.appendChild(c));
  refreshSummary();
}
/* =================================================================
   LANDING CURTAIN — live feeds + stats dashboard
   ================================================================= */
let _curtainRetracted = false;
let _landingInitDone  = false;

/* ── Curtain visibility ── */
function retractCurtain() {
  if (_curtainRetracted) return;
  _curtainRetracted = true;
  document.getElementById("curtainWrapper")?.classList.add("retracted");
  const handle = document.getElementById("curtainHandle");
  if (handle) handle.style.display = "";
  const lbl = document.getElementById("chLabel");
  if (lbl) lbl.textContent = "▼  Latest vulnerabilities";
}

function expandCurtain() {
  _curtainRetracted = false;
  document.getElementById("curtainWrapper")?.classList.remove("retracted");
  const handle = document.getElementById("curtainHandle");
  if (handle) handle.style.display = "flex";
  const lbl = document.getElementById("chLabel");
  if (lbl) lbl.textContent = "▲  Collapse feed";
}

function toggleCurtain() { _curtainRetracted ? expandCurtain() : retractCurtain(); }

/* ── Skeleton placeholders — inside a carousel-track wrapper ── */
function _renderSkeletons(id, n = 8) {
  const el = document.getElementById(id); if (!el) return;
  el.innerHTML = "";
  const track = document.createElement("div"); track.className = "carousel-track";
  for (let i = 0; i < n; i++) {
    const c = document.createElement("div"); c.className = "lcve-card";
    c.innerHTML = `
      <div class="lcve-skel" style="height:9px;width:40%;margin-bottom:8px;border-radius:3px"></div>
      <div class="lcve-skel" style="height:11px;width:60%;margin-bottom:6px"></div>
      <div class="lcve-skel" style="height:8px;width:35%;margin-bottom:10px"></div>
      <div class="lcve-skel" style="height:9px;width:100%;margin-bottom:3px"></div>
      <div class="lcve-skel" style="height:9px;width:80%;margin-bottom:3px"></div>
      <div class="lcve-skel" style="height:9px;width:65%"></div>`;
    track.appendChild(c);
  }
  el.appendChild(track);
}

/* ── ENISA list endpoints (exploited / critical) ── */
async function _fetchEnisaList(type) {
  const url = type === "exploited"
    ? "https://euvdservices.enisa.europa.eu/api/exploitedvulnerabilities"
    : "https://euvdservices.enisa.europa.eu/api/criticalvulnerabilities";
  const r = await proxyFetchWithStatus(url, "json");
  if (r.httpStatus !== 200 || !r.data) return [];
  const raw = Array.isArray(r.data) ? r.data
    : (r.data.data || r.data.items || r.data.vulnerabilities || r.data.results || []);
  return Array.isArray(raw) ? raw.slice(0, 10) : [];
}

/* ── NVD: latest published CVEs ── */
async function _fetchNvdLatest() {
  // NVD API v2 has no sortBy param — filter by pubDate window + sort client-side
  // Try 3-day window first, extend to 7 days if fewer than 5 results
  const fmt = d => d.toISOString().slice(0, 19) + ".000";
  const now = new Date();

  for (const days of [3, 7, 14]) {
    const r = await proxyFetchWithStatus(
      `https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=${fmt(new Date(now - days * 86400000))}&pubEndDate=${fmt(now)}&resultsPerPage=20`,
      "json"
    );
    if (r.httpStatus !== 200 || !r.data) continue;
    const sorted = (r.data.vulnerabilities || [])
      .map(v => v.cve).filter(Boolean)
      .sort((a, b) => (b.published || "").localeCompare(a.published || ""));
    if (sorted.length >= 5) return sorted.slice(0, 5);
    if (sorted.length > 0)  return sorted; // fewer than 5 but window exhausted
  }
  return [];
}

async function _fetchEpssTop5() {
  const r = await proxyFetchWithStatus(
    "https://api.first.org/data/v1/epss?order=!epss&limit=5", "json"
  );
  if (r.httpStatus !== 200 || !r.data?.data) return [];
  return r.data.data; // [{cve, epss, percentile, date}]
}

/* ── EPSS batch: one request for all CVE IDs ── */
async function _fetchEpssBatch(ids) {
  if (!ids.length) return {};
  const r = await proxyFetchWithStatus(
    `https://api.first.org/data/v1/epss?cve=${ids.slice(0, 40).join(",")}`,
    "json"
  );
  if (r.httpStatus !== 200 || !r.data?.data) return {};
  return Object.fromEntries(r.data.data.map(e => [e.cve, parseFloat(e.epss ?? 0)]));
}

/* ── Helpers ── */
function _enisaCveId(e) {
  if (!e) return null;
  const CVE_RE = /CVE-\d{4}-\d+/i;
  const extract = s => { const m = String(s ?? "").match(CVE_RE); return m ? m[0].toUpperCase() : null; };

  // Deep-scan any value recursively until a CVE pattern is found
  function deepScan(node, depth = 0) {
    if (depth > 4 || node == null) return null;
    if (typeof node === "string") return extract(node);
    if (Array.isArray(node)) {
      for (const item of node) { const r = deepScan(item, depth + 1); if (r) return r; }
    } else if (typeof node === "object") {
      for (const v of Object.values(node)) { const r = deepScan(v, depth + 1); if (r) return r; }
    }
    return null;
  }

  // 1. Aliases first (most reliable source for CVE ID on ENISA endpoints)
  if (e.aliases != null) {
    const r = deepScan(e.aliases); if (r) return r;
  }

  // 2. Explicit CVE-named fields
  for (const k of ["cveId", "cve", "vulnerabilityId"]) {
    if (e[k]) { const r = extract(e[k]); if (r) return r; }
  }

  // 3. id / euvdId only if they contain a CVE pattern (not an EUVD-xxx id)
  for (const k of ["id", "euvdId", "euvd_id"]) {
    if (e[k]) { const r = extract(e[k]); if (r) return r; }
  }

  return null;
}

function _scoreHex(s) {
  const n = parseFloat(s);
  if (isNaN(n)) return null;
  if (n >= 9) return "#ef4444";
  if (n >= 7) return "#f59e0b";
  if (n >= 4) return "#2563eb";
  if (n > 0)  return "#22c55e";
  return "#94a3b8";
}

/* ── Build one CVE mini-card ── */
function _createLcveCard(cveId, score, dateStr, desc, epss, cwe, source) {
const card = document.createElement("div"); card.className = "lcve-card";
  if (cveId && /^CVE-/i.test(cveId)) card.dataset.cve = cveId;

  const n        = parseFloat(score);
  const scoreFmt = !isNaN(n) ? n.toFixed(1) : null;
  const scoreHex = scoreFmt ? _scoreHex(n) : null;
  const dateFmt  = dateStr ? new Date(dateStr).toLocaleDateString("en-GB") : "—";
  const descTxt  = desc || "No description available.";

  // Source badge
  const SRC_META = {
    cisa:      { label: "⚠️ CISA KEV",        cls: "lcve-source-cisa"      },
    critical:  { label: "🟠 ENISA Critical",   cls: "lcve-source-critical"  },
    nvd:       { label: "🆕 NVD Latest",        cls: "lcve-source-nvd"       },
    "epss-top": { label: "📈 Top EPSS",         cls: "lcve-source-epss"      },
  };
  const sm = SRC_META[source] || { label: source || "?", cls: "lcve-source-nvd" };
  const srcHtml = `<div><span class="lcve-source ${sm.cls}">${sm.label}</span></div>`;

  // EPSS badge
  let epssHtml = "";
  if (epss != null && !isNaN(epss)) {
    const s = _epssColorStyle(epss);
    epssHtml = `<span class="lcve-epss" style="background:${s.background};color:${s.color};border-color:${s.borderColor}">EPSS ${(epss * 100).toFixed(2)}%</span>`;
  }

  // CWE chip
  const cweId   = cwe ? String(cwe).trim().toUpperCase() : null;
  const cweHtml = cweId
    ? `<span class="lcve-cwe" data-cwe="${esc(cweId)}"><span class="lcve-cwe-id">${esc(cweId)}</span></span>`
    : "";

  const tagsHtml = (epssHtml || cweHtml)
    ? `<div class="lcve-tags">${epssHtml}${cweHtml}</div>` : "";

  card.innerHTML = `
    ${srcHtml}
    <div class="lcve-r1">
      <span class="lcve-id">${esc(cveId || "—")}</span>
      ${scoreHex ? `<span class="lcve-score" style="background:${scoreHex}">${scoreFmt}</span>` : ""}
    </div>
    <div class="lcve-date">${dateFmt}</div>
    <div class="lcve-desc">${esc(descTxt)}</div>
    ${tagsHtml}`;
  return card;
}

/* ── Build unified shuffled carousel from multiple source arrays ──
   Each entry: { items, mapper, sourceTag }
   Returns original card elements for CWE enrichment. */
function _renderUnifiedCarousel(id, sources) {
  const el = document.getElementById(id); if (!el) return [];
  el.innerHTML = "";

  // Interleave: take one card per source in round-robin order
  const queues = sources.map(({ items, mapper, sourceTag }) =>
    items.map(item => ({ mapped: mapper(item), sourceTag }))
  );
  const merged = [];
  const maxLen = Math.max(...queues.map(q => q.length), 0);
  for (let i = 0; i < maxLen; i++)
    queues.forEach(q => { if (i < q.length) merged.push(q[i]); });

  if (!merged.length) {
    el.textContent = "No data available.";
    el.style.cssText = "font-family:var(--font-mono);font-size:11px;color:var(--text-muted);padding:8px 4px";
    return [];
  }

  const CARD_W = 270, GAP = 10, SPEED = 38;
  const originals = [];
  const track = document.createElement("div"); track.className = "carousel-track";

  for (const { mapped: { cveId, score, date, desc, epss, cwe }, sourceTag } of merged) {
    const card = _createLcveCard(cveId, score, date, desc, epss, cwe, sourceTag);
    originals.push(card);
    track.appendChild(card);
  }
  originals.forEach(c => track.appendChild(c.cloneNode(true)));

  const shift = originals.length * (CARD_W + GAP);
  const dur   = Math.round(shift / SPEED);
  track.style.setProperty("--carousel-shift", `-${shift}px`);
  track.style.animationDuration = `${dur}s`;
  el.appendChild(track);
  return originals;
}

/* ── Enrich CWE chips in a carousel container with fetched names ──
   Deduplicates fetches: one network call per unique CWE ID across all containers. */
const _cweNameCache = {};
async function _enrichLandingCwes(...containerIds) {
  // Collect all unique CWE IDs across supplied containers
  const allChips = [];
  containerIds.forEach(id => {
    document.getElementById(id)
      ?.querySelectorAll(".lcve-cwe[data-cwe]")
      .forEach(chip => allChips.push(chip));
  });
  const uniqueIds = [...new Set(allChips.map(c => c.dataset.cwe).filter(Boolean))];
  if (!uniqueIds.length) return;

  // Resolve names: local DB first, network fallback only for misses
  const db = await getCweDb();
  await Promise.allSettled(
    uniqueIds
      .filter(id => !_cweNameCache[id])
      .map(async id => {
        const num = id.replace(/^CWE-/i, "");
        const name = db?.[num]?.n || await fetchCweName(id);
        if (name) _cweNameCache[id] = name;
      })
  );

  // Patch every chip (originals + clones via querySelectorAll)
  containerIds.forEach(id => {
    document.getElementById(id)
      ?.querySelectorAll(".lcve-cwe[data-cwe]")
      .forEach(chip => {
        const name = _cweNameCache[chip.dataset.cwe];
        if (!name || chip.querySelector(".lcve-cwe-name")) return;
        const idEl  = chip.querySelector(".lcve-cwe-id"); if (!idEl) return;
        const sep   = document.createElement("span"); sep.className = "lcve-cwe-sep"; sep.textContent = "—";
        const nameEl = document.createElement("span"); nameEl.className = "lcve-cwe-name"; nameEl.textContent = name;
        chip.appendChild(sep); chip.appendChild(nameEl);
      });
  });
}

let _landingRawSources = null;
const _activeFeedSources = new Set(["nvd","epss-top","cisa","critical"]);

function _rebuildFeedCarousel() {
  if (!_landingRawSources) return;
  const { nvd, epssTop, cisa, critical,
          nvdMapper, epssMapper, cisaMapper, criticalMapper } = _landingRawSources;
  const sources = [
    { tag: "nvd",       items: nvd,      mapper: nvdMapper      },
    { tag: "epss-top",  items: epssTop,  mapper: epssMapper     },
    { tag: "cisa",      items: cisa,     mapper: cisaMapper     },
    { tag: "critical",  items: critical, mapper: criticalMapper },
  ]
    .filter(s => _activeFeedSources.has(s.tag))
    .map(s => ({ items: s.items, mapper: s.mapper, sourceTag: s.tag }));
  _renderUnifiedCarousel("cards-unified", sources);
  _enrichLandingCwes("cards-unified");
}

function _initFeedFilterChips() {
  const container = document.getElementById("feedFilterChips"); if (!container) return;
  const CHIPS = [
    { tag: "nvd",       label: "🆕 NVD Latest"    },
    { tag: "epss-top",  label: "📈 Top EPSS"       },
    { tag: "cisa",      label: "⚠️ CISA KEV"       },
    { tag: "critical",  label: "🟠 ENISA Critical" },
  ];
  container.innerHTML = "";
  CHIPS.forEach(({ tag, label }) => {
    const chip = document.createElement("span");
    chip.className = "feed-filter-chip on";
    chip.dataset.tag = tag;
    const dot = document.createElement("span"); dot.className = "ffc-dot";
    chip.appendChild(dot);
    chip.appendChild(document.createTextNode(label));
    chip.addEventListener("click", () => {
      if (_activeFeedSources.has(tag)) { _activeFeedSources.delete(tag); chip.classList.remove("on"); }
      else                             { _activeFeedSources.add(tag);    chip.classList.add("on");    }
      _rebuildFeedCarousel();
    });
    container.appendChild(chip);
  });
}

/* ── Build mappers + render curtain from already-processed data ── */
function _renderCurtainFromData({ cisaData, enisaCrit, nvdCves, epssTop5, epssMap }) {
  const cisaVulns = cisaData
    ? [...(cisaData.vulnerabilities || [])].sort((a,b) => (b.dateAdded||"").localeCompare(a.dateAdded||"")).slice(0,5)
    : [];

  const cisaMapper = v => ({
    cveId: v.cveID, score: null, date: v.dateAdded,
    desc:  v.shortDescription || null,
    epss:  epssMap[v.cveID] ?? null,
    cwe:   Array.isArray(v.cwes) ? v.cwes[0] : (v.cweID || null),
  });
  const criticalMapper = v => ({
    cveId: _enisaCveId(v),
    score: v.baseScore ?? v.cvssScore ?? null,
    date:  v.datePublished || v.published || null,
    desc:  v.description  || v.summary  || null,
    epss:  epssMap[_enisaCveId(v)] ?? null,
    cwe:   null,
  });
  const nvdMapper = v => {
    const m = v.metrics;
    const s = m?.cvssMetricV31?.[0]?.cvssData?.baseScore
           ?? m?.cvssMetricV40?.[0]?.cvssData?.baseScore
           ?? m?.cvssMetricV30?.[0]?.cvssData?.baseScore
           ?? m?.cvssMetricV2?.[0]?.cvssData?.baseScore ?? null;
    const descs = v.descriptions || [];
    const desc  = (descs.find(d => d.lang === "en") || descs[0])?.value || null;
    const cwes  = (v.weaknesses || []).flatMap(w => (w.description || []).map(d => d.value)).filter(c => /^CWE-\d+$/.test(c));
    return { cveId: v.id, score: s, date: v.published, desc, epss: epssMap[v.id] ?? null, cwe: cwes[0] || null };
  };
  const epssMapper = v => ({
    cveId: v.cve, score: v.score, date: v.date,
    desc: v.desc, epss: parseFloat(v.epss), cwe: v.cwe,
  });

  _landingRawSources = {
    nvd: nvdCves, epssTop: epssTop5, cisa: cisaVulns, critical: enisaCrit.slice(0, 5),
    nvdMapper, epssMapper, cisaMapper, criticalMapper,
  };
  _rebuildFeedCarousel();
  _enrichLandingCwes("cards-unified");
}

/* ── Main init ── */
async function initLanding() {
  if (_landingInitDone) return;
  _landingInitDone = true;
  _initFeedFilterChips();
  _renderSkeletons("cards-unified", 8);

  // Event delegation — covers originals and clones
  document.getElementById("cards-unified")?.addEventListener("click", e => {
    const card = e.target.closest(".lcve-card[data-cve]");
    if (!card) return;
    const input = document.getElementById("searchInput"); if (!input) return;
    input.value = card.dataset.cve;
    input.dispatchEvent(new Event("input"));
    document.getElementById("searchBtn")?.click();
  });

  // Try sessionStorage cache first (avoids all network requests on reload)
  const cached = _curtainLoad();
  if (cached) {
    if (cached.cisaData) _cisaKevCache = cached.cisaData; // restore module-level CISA cache
    _renderCurtainFromData(cached);
    return;
  }

  // Progressive render — each source triggers a carousel rebuild on arrival
  const ps = { cisaData: null, enisaCrit: [], nvdCves: [], epssTop5: [], epssMap: {} };

  // Debounce: avoids double DOM rebuild when 2 sources resolve near-simultaneously
  let _partialTimer = null;
  const _partial = () => { clearTimeout(_partialTimer); _partialTimer = setTimeout(() => _renderCurtainFromData(ps), 60); };

  const p1 = getCisaKev().then(d => { ps.cisaData = d || null; if (d) _cisaKevCache = d; _partial(); }).catch(() => {});
  const p2 = _fetchEnisaList("critical").then(d => { ps.enisaCrit = d || []; _partial(); }).catch(() => {});
  const p3 = _fetchNvdLatest().then(d => { ps.nvdCves = d || []; _partial(); }).catch(() => {});

  // EPSS top5 — sequential NVD lookups, enriches after initial render
  const p5 = _fetchEpssTop5().then(async raw => {
    if (!raw?.length) return;
    const details = [];
    for (const e of raw) {
      details.push(await proxyFetch(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(e.cve)}`, "json"));
      await wait(300);
    }
    ps.epssTop5 = raw.map((e, i) => {
      const nvd = details[i]?.vulnerabilities?.[0]?.cve || null;
      const m = nvd?.metrics;
      const score = m?.cvssMetricV31?.[0]?.cvssData?.baseScore
                 ?? m?.cvssMetricV40?.[0]?.cvssData?.baseScore
                 ?? m?.cvssMetricV30?.[0]?.cvssData?.baseScore
                 ?? m?.cvssMetricV2?.[0]?.cvssData?.baseScore ?? null;
      const descs = nvd?.descriptions || [];
      const desc = (descs.find(d => d.lang === "en") || descs[0])?.value || null;
      const cwes = (nvd?.weaknesses || []).flatMap(w => (w.description || []).map(d => d.value)).filter(c => /^CWE-\d+$/.test(c));
      return { cve: e.cve, epss: e.epss, date: nvd?.published || null, score, desc, cwe: cwes[0] || null };
    });
    // Batch EPSS now that CISA + NVD IDs are known
    const batchIds = new Set([
      ...(ps.cisaData?.vulnerabilities || []).slice(0, 5).map(v => v.cveID).filter(Boolean),
      ...ps.nvdCves.map(v => v.id).filter(Boolean),
    ]);
    ps.epssMap = await _fetchEpssBatch([...batchIds]).catch(() => ({}));
    raw.forEach(e => { ps.epssMap[e.cve] = parseFloat(e.epss); });
    _partial();
  }).catch(() => {});

  // Save to sessionStorage cache once everything has settled
  Promise.allSettled([p1, p2, p3, p5]).then(() => _curtainSave({ ...ps }));
}

/* Refresh charts on theme toggle */
  new MutationObserver(() => { refreshAllEpssColors(); _rebuildFeedCarousel(); })
  .observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });