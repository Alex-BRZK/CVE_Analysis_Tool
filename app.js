/**
 * CVE Analysis Tool (CAT) — app.js
 * Copyright (C) 2024-2026  Alexis Broniarczyk
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
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
  { name:"LibreOffice", url: cve=>`https://www.libreoffice.org/about-us/security/advisories/${cve.toLowerCase()}/` },
  { name:"PostgreSQL",  url: cve=>`https://www.postgresql.org/support/security/${cve}/` },
  { name:"Oracle",      url: cve=>`https://www.oracle.com/security-alerts/alert-${cve.toLowerCase()}.html` },
  { name:"Xen",         url: _=>`https://xenbits.xen.org/xsa/xsa.json` },
  { name:"CISA",        url: cve=>`https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${cve}&field_date_added_wrapper=all&field_cve=&sort_by=field_date_added&items_per_page=20&url=` },
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
  LibreOffice:cve=>`https://www.libreoffice.org/about-us/security/advisories/${cve.toLowerCase()}/`,
  PostgreSQL: cve=>`https://www.postgresql.org/support/security/${cve}/`,
  Oracle:     cve=>`https://www.oracle.com/security-alerts/alert-${cve.toLowerCase()}.html`,
  Xen:        _=>`https://xenbits.xen.org/xsa/xsa.json`,
  CISA:       _=>`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`,
};

const PROXY    = "__WORKER_PROXY__";
const DELAY_MS = 400;

/* =================================================================
   PROXY
   ================================================================= */
const MAX_CONCURRENT = 6;
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
(function(){ document.documentElement.setAttribute("data-theme", localStorage.getItem("theme") || "light"); })();

/* =================================================================
   TEXT UTILITIES
   ================================================================= */
function extractCveIds(s) { return [...new Set((s.match(/CVE-\d{4}-\d{4,7}/gi) || []).map(c => c.toUpperCase()))]; }
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
   CVE PERSISTENCE + COMPLEMENTARY CACHE
   ─────────────────────────────────────────────────────────────────
   Master list : localStorage  "cat_cves"      — max 50 IDs (oldest→newest)
   Data cache  : localStorage  "cat_cve_{ID}" — 25 most recent, TTL 7 days
               : sessionStorage "cat_cve_{ID}"— next 25 oldest, TTL 4h
   Beyond 50   : displayed only, no storage
   ================================================================= */
const MAX_CVES    = 50;
const MAX_LS_DATA = 25;                        // newest 25 → localStorage
const MAX_SS_DATA = 25;                        // next oldest 25 → sessionStorage
const LS_TTL_MS   = 7 * 24 * 60 * 60 * 1000; // 7 days
const SS_TTL_MS   = 4 * 60 * 60 * 1000;       // 4 hours

/* ── Master list helpers ── */
function storageGetCves() {
  try { return JSON.parse(localStorage.getItem("cat_cves") || "[]"); } catch { return []; }
}
function storageSetCves(l) { localStorage.setItem("cat_cves", JSON.stringify(l)); }

/* ── Target store for a given CVE ──
   Returns localStorage, sessionStorage, or null (not in list → don't save). */
function _targetStore(list, cve) {
  const idx = list.indexOf(cve);
  if (idx === -1) return null;                         // not in master list → don't store
  return idx >= list.length - MAX_LS_DATA ? localStorage : sessionStorage;
}

/* ── Add a CVE to the master list and handle tier migration ── */
function storageAddCve(cve) {
  const l = storageGetCves();
  if (l.includes(cve)) return;
  l.push(cve);                                         // newest at end

  if (l.length > MAX_CVES) {
    const evicted = l.shift();                         // drop oldest
    _dataDel(evicted);                                 // delete its data from both stores
  }
  storageSetCves(l);

  // When the list grows past MAX_LS_DATA the CVE that sits at the
  // boundary (index length-MAX_LS_DATA-1) has just crossed from
  // localStorage → sessionStorage. Migrate its data.
  const migrateIdx = l.length - MAX_LS_DATA - 1;
  if (migrateIdx >= 0) {
    const cveToMigrate = l[migrateIdx];
    const key = `cat_cve_${cveToMigrate}`;
    const data = localStorage.getItem(key);
    if (data) {
      try {
        _writeWithLRU(sessionStorage, key, data);
        localStorage.removeItem(key);
      } catch { /* keep in localStorage if sessionStorage full */ }
    }
  }
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
function _dataDel(cve) {
  const k = `cat_cve_${cve}`;
  localStorage.removeItem(k);
  sessionStorage.removeItem(k);
}

function _dataDelAll() {
  const prefix = "cat_cve_";
  [localStorage, sessionStorage].forEach(store => {
    Object.keys(store).filter(k => k.startsWith(prefix)).forEach(k => store.removeItem(k));
  });
}

/* ── LRU-aware write (safety net for quota) ──
   Only evicts entries whose CVE is in the SAME tier in the current master list,
   so it never wrongly evicts a CVE from the other tier. */
function _writeWithLRU(store, key, serialised) {
  const isLS   = store === localStorage;
  const list   = storageGetCves();
  const lsSet  = new Set(list.slice(list.length - MAX_LS_DATA));
  const ssSet  = new Set(list.slice(0, list.length - MAX_LS_DATA));
  const allowedSet = isLS ? lsSet : ssSet;

  for (let attempt = 0; attempt < 60; attempt++) {
    try { store.setItem(key, serialised); return; }
    catch (e) {
      if (e.name !== "QuotaExceededError" && e.name !== "NS_ERROR_DOM_QUOTA_REACHED") return;
      // Find oldest entry that belongs to this tier
      let oldestKey = null, oldestTs = Infinity;
      for (let i = 0; i < store.length; i++) {
        const k = store.key(i);
        if (!k || !k.startsWith("cat_cve_") || k === key) continue;
        const id = k.replace("cat_cve_", "");
        if (!allowedSet.has(id)) continue;             // belongs to other tier → don't touch
        try {
          const ts = JSON.parse(store.getItem(k))?.ts ?? 0;
          if (ts < oldestTs) { oldestTs = ts; oldestKey = k; }
        } catch { oldestKey = k; oldestTs = 0; }
      }
      if (!oldestKey) return;
      store.removeItem(oldestKey);
    }
  }
}

/* ── Save after Phase-2 settles ── */
function sessionSave(cve, ctx, cvssBase) {
  const list   = storageGetCves();
  const target = _targetStore(list, cve);
  if (!target) return;                                 // CVE not in master list → don't store

  const isLS  = target === localStorage;
  const other = isLS ? sessionStorage : localStorage;
  const ttl   = isLS ? LS_TTL_MS : SS_TTL_MS;

  const { statuses, urls } = _getDotStatuses(cve);
  const payload = {
    ts: Date.now(), ttl,
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
    },
    cvssBase,
    dotStatuses: statuses,
    dotUrls:     urls,
  };

  const key        = `cat_cve_${cve}`;
  const serialised = JSON.stringify(payload);
  other.removeItem(key);                               // clean up if CVE was in wrong tier
  _writeWithLRU(target, key, serialised);
}

/* ── Load (localStorage first, then sessionStorage) ── */
function sessionLoad(cve) {
  const key = `cat_cve_${cve}`;
  for (const store of [localStorage, sessionStorage]) {
    try {
      const raw = store.getItem(key);
      if (!raw) continue;
      const p = JSON.parse(raw);
      if (Date.now() - p.ts > (p.ttl ?? SS_TTL_MS)) { store.removeItem(key); continue; }
      return p;
    } catch { continue; }
  }
  return null;
}

/* ── Remove / clear ── */
function sessionRemove(cve) { _dataDel(cve); }
function sessionClearAll()  { _dataDelAll(); }

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
  const l = {"v4.0":12,"v3.1":8,"v3.0":8,"v2.0":6}[version];
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
async function fetchCweName(cweId) {
  const num = cweId.replace(/^CWE-/i, "");
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
      let cweId = d.cweId || null, cweName = null;
      if (d.description) {
        const m = String(d.description).match(/^(CWE-\d+)\s+([\s\S]+)/i);
        if (m) { if (!cweId) cweId = m[1].toUpperCase(); cweName = m[2].trim(); }
        else if (!/^CWE-\d+$/i.test(d.description.trim())) cweName = d.description;
      }
      if (!cweId && d.type === "text" && d.description) { const m2 = String(d.description).match(/\b(CWE-\d+)\b/i); if (m2) cweId = m2[1].toUpperCase(); }
      if (cweId || (d.type === "CWE" && cweName)) pushCwe(list, cweId, cweName, source);
    }));
  }

  extractCwesFromContainer(cna, "CVEList");
  // ADP containers
  getAdpContainers(cveListData).forEach(adp => extractCwesFromContainer(adp, "CVEList"));

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
function collectRefs(cvl, nvd, rhC, suC, msV, ubRaw, cisaData, notAffectedSources = new Set(), excludedUrls = new Set()) {
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
  if (r.httpStatus === 0) return { desc: null, notAffected: null, networkError: true };
  const html = r.data;
  if (!html || r.httpStatus === 404) return { desc: null, notAffected: null, networkError: false };
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
  return { desc, notAffected, networkError: false };
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
async function fetchLibreOfficeData(cve) {
  const url = `https://www.libreoffice.org/about-us/security/advisories/${cve.toLowerCase()}/`;
  const result = await proxyFetchWithStatus(url, "text");
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
   CSAF / LEGACY HELPERS
   ================================================================= */
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
function createTemplateCard() {
  const card = document.createElement("div"); card.className = "cve-card template"; card.id = "templateCard";
  const fakeChips = SOURCE_CONFIG.map(s => `<a class="source-chip"><span class="dot dot-wait"></span>${esc(s.name)}</a>`).join("");
  card.innerHTML = `<div class="template-label">Example CVE card</div>
    <div class="card-top"><div class="card-meta-left">
      <div class="card-meta-row"><span class="assigner">mitre</span><span class="sep">•</span><span class="date">01/01/2024</span></div>
      <div class="cve-title">CVE-XXXX-XXXXX</div></div>
      <div class="card-chips-right">${fakeChips}</div></div>
    <div class="desc-table">
      <div class="desc-row"><div class="desc-sources"><span class="source-badge badge-cvelist">CVEList</span><span class="source-badge badge-nvd">NVD</span></div>
        <div class="desc-text">Multiple sources sharing the same description are grouped on one row.</div></div>
      <div class="desc-row"><div class="desc-sources"><span class="source-badge badge-microsoft">Microsoft</span></div>
        <div class="desc-text">A different description from another source appears on its own row.</div></div></div>
    <div class="cvss-section">
      <span class="cvss-badge bg-critical"><span class="version">CVSS v3.1</span><span class="score">9.8</span><span class="sources">NVD</span></span>
      <span class="cvss-badge bg-high"><span class="version">CVSS v2.0</span><span class="score">7.5</span><span class="sources">NVD</span></span></div>
    <div class="cwe-section">
      <a class="cwe-chip" href="https://cwe.mitre.org/data/definitions/416.html" target="_blank"><span class="cwe-chip-id">CWE-416</span><span class="cwe-chip-sep"> — </span><span class="cwe-chip-name">Use After Free</span><span class="cwe-chip-srcs"> (CVEList, NVD)</span></a></div>
    <details class="refs-details">
      <summary class="refs-summary"><span class="refs-arrow">▶</span><span>References</span><span class="refs-count">3</span></summary>
      <div class="refs-body"><div class="ref-row"><div class="ref-src-badges"><span class="source-badge badge-cvelist">CVEList</span></div>
        <a class="ref-link" href="#" target="_blank">https://example.com/advisory/2024-001</a></div></div></details>`;
  return card;
}
function createSourceBadge(name, url) {
  const el = document.createElement(url ? "a" : "span");
  el.className = `source-badge badge-${name.toLowerCase()}`; el.textContent = name;
  if (url) { el.href = url; el.target = "_blank"; el.title = url; }
  return el;
}
function createDescRow(sources, text) {
  const row = document.createElement("div"); row.className = "desc-row";
  row.dataset.sources = sources.length ? sources.map(s => s.name).join(",") : "?";
  const left = document.createElement("div"); left.className = "desc-sources";
  if (sources.length) sources.forEach(s => left.appendChild(createSourceBadge(s.name, s.url)));
  else { const ph = document.createElement("span"); ph.className = "source-badge"; ph.textContent = "?"; left.appendChild(ph); }
  const right = document.createElement("div"); right.className = "desc-text"; right.textContent = text || "";
  row.appendChild(left); row.appendChild(right); return row;
}
function createCvssBadge({ version, score, vector, sources }) {
  const ve = encodeURIComponent(vector);
  const urlMap = {
    "v2.0": `https://nvd.nist.gov/vuln-metrics/cvss/v2-calculator?vector=${ve}&source=NIST`,
    "v3.0": `https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=${ve}&version=3.0&source=NIST`,
    "v3.1": `https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator?vector=${ve}&version=3.1&source=NIST`,
    "v4.0": `https://nvd.nist.gov/vuln-metrics/cvss/v4-calculator?vector=${ve}&version=4.0&source=NIST`,
  };
  const a = document.createElement("a"); a.className = `cvss-badge ${cvssColorClass(score)}`;
  a.dataset.sources = sources.join(",");
  a.dataset.cvssVersion = version;
  a.href = urlMap[version] || "#"; a.target = "_blank"; a.title = `Vector: ${vector}`;
  a.innerHTML = `<span class="version">CVSS ${esc(version)}</span><span class="score">${esc(String(score))}</span><span class="sources">${esc(sources.join(", "))}</span>`;
  return a;
}
function createCweSection(cweList) {
  if (!cweList.length) return null;
  const section = document.createElement("div"); section.className = "cwe-section";
  cweList.forEach(({ id, name, sources }) => {
    const num = id.slice(4), href = `https://cwe.mitre.org/data/definitions/${num}.html`;
    const chip = document.createElement("a"); chip.className = "cwe-chip"; chip.href = href; chip.target = "_blank"; chip.title = href;
    chip.dataset.sources = sources.join(",");
    const idEl = document.createElement("span"); idEl.className = "cwe-chip-id"; idEl.textContent = id; chip.appendChild(idEl);
    if (name) {
      const sep = document.createElement("span"); sep.className = "cwe-chip-sep"; sep.textContent = " — ";
      const nm = document.createElement("span"); nm.className = "cwe-chip-name"; nm.textContent = name;
      chip.appendChild(sep); chip.appendChild(nm);
    }
    const sr = document.createElement("span"); sr.className = "cwe-chip-srcs"; sr.textContent = ` (${sources.join(", ")})`; chip.appendChild(sr);
    section.appendChild(chip);
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
  document.getElementById("templateCard")?.remove();
  const skeleton = createSkeletonCard(cve);
  container.prepend(skeleton);

  const fp = {
    cveList: fetchCveListData(cve),
    nvd:     fetchNvdData(cve),
    rhOld: null, rhCsaf: null, suse:   null, debian: null,
    ubuntu: null, msrc:  null, amazon: null, lbo:    null,
    pg:    null, oracle: null, xen:    null, cisa:   null,
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
  }

  // Rebuild all card sections from current ctx state
  function refreshCard() {
    // ── collect all (name, url, text) description candidates in priority order ──
    const allDescItems = [];
    const cveListDesc = normalizeText(ctx.cveListData?.containers?.cna?.descriptions?.[0]?.value);
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

    if (cveListDesc) allDescItems.push({ name:"CVEList",     url:DESC_SOURCE_URLS.CVEList(cve),     text:cveListDesc });
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
    const refs = collectRefs(ctx.cveListData, ctx.nvdData, ctx.rhCsaf, ctx.suseCsaf, ctx.msrcData?.vuln, ctx.ubuntuData?.rawData, ctx.cisaData, notAff, excludedUrls);
    renderRefsBody(refsBody, refsCountEl, refs);

    applyFilter();
  }

  async function refreshCwe() {
    const cweAll = collectCweList(ctx.cveListData, ctx.nvdData, ctx.rhCsaf, ctx.suseCsaf, ctx.msrcData?.vuln, ctx.cisaData);
    await Promise.all(cweAll.filter(c => !c.name).map(async c => { c.name = await fetchCweName(c.id); }));
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
      if (cna) extractMetricsFromContainer(cna, "CVEList", cvssBase);
      // ADP containers (CVE Program enrichment, introduced 2024-07-31)
      getAdpContainers(cveListData).forEach(adp => extractMetricsFromContainer(adp, "CVEList", cvssBase));
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
    metaLeft.appendChild(metaRow);
    const titleEl = document.createElement("div"); titleEl.className = "cve-title"; titleEl.textContent = cve; metaLeft.appendChild(titleEl);
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
    const initRefs = collectRefs(cveListData, ctx.nvdData, null, null, null, null, null, new Set(), excludedUrls);
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

    Promise.allSettled([fp.rhOld, fp.rhCsaf, fp.suse, fp.debian, fp.ubuntu, fp.msrc, fp.amazon, fp.lbo, fp.pg, fp.oracle, fp.xen, fp.cisa])
      .then(() => { refsSpinnerEl.style.display = "none"; sessionSave(cve, ctx, cvssBase); });

  } catch (err) {
    const errDiv = document.createElement("div"); errDiv.className = "cve-error"; errDiv.textContent = `⚠ ${err.message}`;
    try { container.replaceChild(errDiv, skeleton); } catch { container.prepend(errDiv); }
  }
}

/* =================================================================
   SOURCE FILTER
   ================================================================= */
const ALL_SOURCES    = ["NVD","CVEList","RedHat","SUSE","Debian","Ubuntu","Microsoft","Amazon","LibreOffice","PostgreSQL","Oracle","Xen","CISA"];
const LOCKED_SOURCES = new Set(["NVD","CVEList"]);
const activeSources  = new Set(ALL_SOURCES);

function applyFilter() {
  document.querySelectorAll(".desc-row[data-sources]").forEach(row => {
    const srcs = row.dataset.sources.split(",");
    const vis  = srcs.filter(s => LOCKED_SOURCES.has(s) || activeSources.has(s));
    row.style.display = vis.length ? "" : "none";
    row.querySelectorAll(".source-badge").forEach(b => {
      const n = b.textContent.trim();
      b.style.display = (!n || n === "?" || LOCKED_SOURCES.has(n) || activeSources.has(n)) ? "" : "none";
    });
  });
  document.querySelectorAll(".cvss-badge[data-sources]").forEach(badge => {
    const srcs = badge.dataset.sources.split(",");
    const vis  = srcs.filter(s => LOCKED_SOURCES.has(s) || activeSources.has(s));
    badge.style.display = vis.length ? "" : "none";
    const span = badge.querySelector(".sources"); if (span) span.textContent = vis.join(", ");
  });
  document.querySelectorAll(".ref-row[data-sources]").forEach(row => {
    const srcs = row.dataset.sources.split(",");
    const vis  = srcs.some(s => LOCKED_SOURCES.has(s) || activeSources.has(s));
    row.style.display = vis ? "" : "none";
    row.querySelectorAll(".source-badge").forEach(b => {
      const n = b.textContent.trim();
      b.style.display = (!n || LOCKED_SOURCES.has(n) || activeSources.has(n)) ? "" : "none";
    });
  });
  document.querySelectorAll(".cwe-chip[data-sources]").forEach(chip => {
    const srcs = chip.dataset.sources.split(",");
    const vis  = srcs.filter(s => LOCKED_SOURCES.has(s) || activeSources.has(s));
    chip.style.display = vis.length ? "" : "none";
    const srEl = chip.querySelector(".cwe-chip-srcs"); if (srEl) srEl.textContent = vis.length ? ` (${vis.join(", ")})` : "";
  });
  // Hide/show source chips (status dots in card header)
  document.querySelectorAll(".source-chip[data-source]").forEach(chip => {
    const src = chip.dataset.source;
    chip.style.display = (LOCKED_SOURCES.has(src) || activeSources.has(src)) ? "" : "none";
  });
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
  const container = document.getElementById("filterChips"); if (!container) return;
  // Restore visibles sources from localStorage
  try {
    const saved = localStorage.getItem("cat_filters");
    if (saved) {
      const savedArr = JSON.parse(saved);
      activeSources.clear();
      savedArr.forEach(s => { if (ALL_SOURCES.includes(s)) activeSources.add(s); });
      LOCKED_SOURCES.forEach(s => activeSources.add(s)); // toujours actives
    }
  } catch {}
  ALL_SOURCES.forEach(src => {
    const chip = document.createElement("span");
    const isOn = LOCKED_SOURCES.has(src) || activeSources.has(src);
    chip.className = "filter-chip" + (LOCKED_SOURCES.has(src) ? " locked" : isOn ? " on" : "");
    chip.dataset.src = src;
    const dot = document.createElement("span"); dot.className = "fc-dot";
    chip.appendChild(dot); chip.appendChild(document.createTextNode(src));
    if (!LOCKED_SOURCES.has(src)) {
      chip.addEventListener("click", () => {
        if (activeSources.has(src)) { activeSources.delete(src); chip.classList.remove("on"); }
        else { activeSources.add(src); chip.classList.add("on"); }
        _saveFilterState();
        applyFilter();
      });
    }
    container.appendChild(chip);
  });
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
  document.getElementById("cveResults").appendChild(createTemplateCard());
  input.addEventListener("input", () => { btn.disabled = !extractCveIds(input.value.toUpperCase()).length; });
  initFilterChips();
  initFieldChips();

  // Restore the sort from localStorage
  const savedSort = localStorage.getItem("cat_sort");
  if (savedSort) {
    _currentSort = savedSort;
    const sortSel = document.getElementById("sortSelect");
    if (sortSel) sortSel.value = savedSort;
  }

  const saved = storageGetCves();
  if (saved.length) {
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
  const container = document.getElementById("cveResults");
  if (!document.getElementById("templateCard") && !document.querySelectorAll(".cve-card:not(.template)").length)
    container.appendChild(createTemplateCard());
  updateClearSection(); refreshSummary();
}

function clearAllCves() {
  document.querySelectorAll(".cve-card:not(.template)").forEach(c => c.remove());
  displayedCVEs.clear(); cveData.clear(); storageClearCves(); sessionClearAll();
  const container = document.getElementById("cveResults");
  if (!document.getElementById("templateCard")) container.appendChild(createTemplateCard());
  updateClearSection(); refreshSummary();
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
      extractMetricsFromContainer(cna2, "CVEList", stored.cvssBase);
      getAdpContainers(data).forEach(adp => extractMetricsFromContainer(adp, "CVEList", stored.cvssBase));
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