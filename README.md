# 🐱 CVE Analysis Tool (CAT)

> A client-side, zero-dependency web application that aggregates CVE vulnerability data in real time from multiple official sources — no installation required / no account required.

![Version](https://img.shields.io/badge/version-v1.0-blue)
![License](https://img.shields.io/badge/license-GPL--3.0-green)
![Status](https://img.shields.io/badge/status-active-brightgreen)

---
## 📖 Overview


**CVE Analysis Tool** (CAT) is an open-source, browser-based tool designed to give security analysts and researchers a **centralized, multi-source view** of any CVE identifier. Simply enter one or several CVE IDs, and the tool simultaneously queries all configured data sources, deduplicates the results, and displays a unified card with descriptions, CVSS scores, CWE identifiers, and source availability statuses.

Everything runs **100% client-side** — no backend, no installation, no data sent to a third-party server (except through the CORS proxy). All information comes from external sources, and each of them is systematically referenced to ensure **complete transparency** on the origin of the data.  **[Click here](https://alex-brzk.github.io/CVE_Analysis_Tool/)**

---

## ✨ Features

- **Multi-CVE search** — Paste any block of text containing CVE identifiers; a regex automatically extracts all valid IDs and deduplicates them.
- **Parallel data fetching** — All sources are queried simultaneously to minimize load time.
- **Description deduplication** — Identical descriptions from multiple sources are merged into a single row with all source badges listed.
- **CVSS score aggregation** — Scores from all sources are collected, deduplicated by `(version, score, vector)`, and displayed as colour-coded badges (None / Low / Medium / High / Critical). Each badge links to the NIST CVSS calculator with the vector pre-filled.
- **CVSS v2.0, v3.0, v3.1 and v4.0 support**
- **CWE chips** — CWE identifiers are displayed as clickable chips linking to the MITRE CWE database.
- **Source status dots** — Each source shows a real-time coloured indicator (grey → loading, green → confirmed, red → not found, orange → not affected, black/white → network error).
- **Progressive loading** — Skeleton cards are rendered immediately while data loads in the background.
- **Source filtering** — A filter panel lets you show/hide specific sources without reloading.
- **Light / Dark theme** — Persisted in `localStorage`.
- **Zero dependencies** — Vanilla JS, custom CSS, no framework, no bundler.

---

## 🔌 Data Sources

| Source | Type | Data provided |
|---|---|---|
| **CVEProject / CVEList** | GitHub JSON (v5) | Description, CNA data, scores, CWE, references |
| **NVD (NIST)** | REST API v2 | Enriched description, CVSS v2/v3/v4, CWE, references |
| **Red Hat** | JSON API + CSAF VEX | Red Hat-specific description, CVSS, affected product status and references |
| **SUSE** | CSAF VEX (FTP) | SUSE-specific CVSS scores, description and references|
| **Debian** | HTML scraping | Description, package applicability status and references |
| **Ubuntu** | Security page | Ubuntu-specific CVSS scores and descriptions, package applicability status and references |
| **Microsoft MSRC** | Security Response Center | Microsoft-specific CVSS scores and description and bulletin existence check |
| **Amazon Linux** | ALAS page | Amazon linux-specific CVSS scores and description |
| **LibreOffice** | Security advisories | Advisory description |
| **PostgreSQL** | Security page | Postgresql-specific CVSS scores and description |
| **Oracle** | Security alerts | Advisory description |
| **CISA** | Known Exploited Vulnerabilities | Description, CWes and references |
| **Xen** | Security advisories | Advisory description |


---

## 🤝 Contributing

All contributions, ideas, and suggestions are welcome!

Whether you want to add a new data source, fix a bug, improve the UI, or suggest a feature — feel free to get involved. The best way to start is to **[open a new ticket via GitHub Issues](https://github.com/Alex-BRZK/CVE_Analysis_Tool/issues/new/choose)**. Please describe your idea or the problem you encountered as clearly as possible so it can be discussed and prioritised.

---

## 📄 License

This project is licensed under the **GNU General Public License v3.0 (GPL-3.0)**.

See the [`LICENSE`](./LICENSE) file for the full terms.

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
