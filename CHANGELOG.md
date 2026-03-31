# Changelog

All notable changes to Glinthaven will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0-alpha] — 2026-03-30

### Added
- **WiGLE Integration** — Added WiGLE source for tracking and looking up WiFi networks by MAC address (BSSID) and SSID
- **Pulsedive Integration** — Added Pulsedive source for advanced threat intelligence and risk scoring of IPs, Domains, and URLs
- **IPWhois Integration** — Added IP geolocation and network intelligence via ipwho.is
- **GeoIP Integration** — Added IP-API.com integration for advanced hosting and proxy detection
- **ARIN RDAP Integration** — Added ARIN RDAP integration for regional IP registry lookup
- **Session Notes** — Added a temporary scratchpad to store ephemeral notes via `note`, `notes`, and `note-clear` commands
- **Command Autocomplete** — Added terminal command autocomplete using the <kbd>Tab</kbd> key, featuring an inline ghost-text preview. The feature can be toggled in the Settings menu
- **New IOC Types** — Added auto-detection for MAC addresses, ASNs (Autonomous System Numbers), and SSIDs (using the `ssid:` prefix)
- **Netlas.io Integration** — Added Netlas source for infrastructure mapping and domain-level threat intelligence
- **HackerTarget Integration** — Added DNS enumeration, Reverse IP lookup, Subdomain Discovery, and asynchronous MTR Traceroute map generation
- **BGPView Integration** — Added unauthenticated BGP routing capabilities, mapping IP NetBlock allocations and ASN tracking
- **Certificate Transparency (crt.sh)** — Added crt.sh proxy to passively hunt for SSL/TLS certificates and wildcard subdomains
- **SecurityTrails Integration** — Added historical DNS mapping and current WHOIS registry context via SecurityTrails
- **Have I Been Pwned (HIBP)** — Added email breach verification indexing, equipped with explicit credential stuffing and Combo List detection algorithms
- **Single-Source Filtering** — Users can now hone their OSINT queries to a single integration by appending `-s` or `--source` (e.g., `8.8.8.8 -s bgpview`)
- **Legal Safeguards** — Introduced an initial Terms of Service UI acceptance modal and explicit legal disclaimers to protect users and the platform

## [0.1.0-alpha] — 2026-03-24

### Added
- **urlscan.io Integration** — Added urlscan.io source for sandbox scanning of domains, URLs, and IPs
- **Source Toggles** — Added checkboxes in the settings menu to selectively enable or disable specific threat intel sources
- **Source Grouping** — Grouped the settings UI logically by function (General Threat Intel, Infrastructure, etc.)
- **Quick Setup Wizard** — Added a dynamic setup wizard that auto-launches for new users (or via `setup` command) to configure API keys
- **Mobile Support** — Improved mobile layout support with dynamic viewport height to prevent terminal clipping

## [0.0.1-alpha] — 2026-03-22

First alpha release of Glinthaven.

### Added

- **CLI Terminal Interface** — Full terminal emulator in the browser with command input, scrollable output, and blinking caret
- **IOC Auto-Detection** — Automatically identifies 9 IOC types from raw input:
  - IPv4 and IPv6 addresses
  - Domains (FQDN)
  - URLs (http/https)
  - File hashes (MD5, SHA-1, SHA-256)
  - Email addresses
  - CVE IDs
- **Threat Intelligence Sources** — Parallel queries to 4 services:
  - VirusTotal (files, IPs, domains, URLs)
  - AbuseIPDB (IP reputation)
  - Shodan (host reconnaissance)
  - AlienVault OTX (general IOC data, works without API key)
- **Streaming Results** — Results appear as each source responds, no waiting for all to finish
- **Severity Indicators** — Color-coded result blocks (green/amber/red) based on threat level
- **Built-in Commands** — `help`, `search`, `clear`, `history`, `settings`, `about`
- **Help System** — 5 topics: `commands`, `ioc`, `start`, `examples`, `api`
- **Command History** — Up/Down arrow navigation, persisted in `sessionStorage`
- **API Key Management** — Settings modal for configuring keys, stored in `localStorage`
- **Landing Page** — Animated hero with logo, IOC type badges, and "Launch Terminal" button
- **Keyboard Shortcuts** — Enter to launch from landing, Escape to close modals
- **Responsive Design** — Works on mobile, tablet, and desktop
- **URL Parameter** — `?terminal` or `?t` to skip landing and go straight to the terminal
- **Plugin Architecture** — Each threat intel source is a self-contained module in `src/sources/`. Adding a new source requires creating one file and registering it — see `CONTRIBUTING.md`

### Technical Details

- Built with **Vite 5** + vanilla JavaScript (no framework)
- Self-contained source plugins in `src/sources/` with a central registry
- Production bundle: **23.7 KB JS** (7.7 KB gzipped) + **11.9 KB CSS** (3.1 KB gzipped)
- Zero runtime dependencies — dev dependency is Vite only
- All API calls are client-side; no backend server required

### Known Limitations

- Some threat intel APIs (VirusTotal, AbuseIPDB) may block browser CORS requests — a lightweight proxy may be needed for production deployments
- Email IOC type is detected but no email-specific threat intel source is integrated yet
- No result caching — repeated queries re-fetch from APIs
- Rate limiting is handled per-service but not surfaced in a unified way
