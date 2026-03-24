<p align="center">
  <img src="public/favicon.svg" width="64" height="64" alt="Glinthaven logo" />
</p>

<h1 align="center">Glinthaven</h1>

<p align="center">
  <strong>Where security research and OSINT find their flow.</strong><br/>
  Paste an IP, domain, hash, URL, email, or CVE and get results from multiple sources in seconds.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-0.1.0--alpha-blue.svg" alt="Version" />
  <img src="https://img.shields.io/badge/license-MIT-blue" alt="License" />
  <img src="https://img.shields.io/badge/bundle-7.5KB_gzipped-green" alt="Bundle size" />
</p>

---

## What is Glinthaven?

Glinthaven is a lightweight web app that lets you look up security Indicators of Compromise (IOCs) through a familiar terminal-style interface. Just paste an indicator — the app auto-detects the type, queries multiple threat intelligence sources in parallel, and displays color-coded results right in the terminal.

**No backend required.** Everything runs in your browser.

## Features

- **Auto-detect IOC type** — IPv4, IPv6, domain, URL, MD5/SHA1/SHA256 hash, email, CVE
- **4 threat intel sources** — VirusTotal, AbuseIPDB, Shodan, AlienVault OTX
- **Parallel queries** — all sources queried simultaneously with streaming results
- **CLI interface** — command history (↑/↓), built-in help, familiar terminal UX
- **Newcomer-friendly** — quick-start guide, examples, contextual tips
- **Tiny footprint** — 7.5 KB JS + 3.1 KB CSS (gzipped)
- **Private** — API keys stored locally in your browser, never sent to third parties

## Quick Start

```bash
# Clone and install
git clone <repo-url> glinthaven
cd glinthaven
npm install

# Start the dev server
npm run dev
# → http://localhost:5173
```

1. Open http://localhost:5173 and click **Launch Terminal** (or press Enter)
2. Type `settings` to add your API keys (see [API Keys](#api-keys) below)
3. Paste any IOC and press Enter — that's it!

Try `help start` in the terminal for a guided walkthrough.

## Commands

| Command | Description |
|---------|-------------|
| `<ioc>` | Paste any IOC directly to search it |
| `<ioc> --debug` | Search with debug info (latency, HTTP status, endpoint) |
| `search <ioc>` | Explicitly search an IOC |
| `debug [on\|off]` | Toggle persistent debug mode for all searches |
| `help [topic]` | Show help (`commands`, `ioc`, `start`, `examples`, `api`) |
| `settings` | Open API key configuration |
| `clear` | Clear the terminal |
| `history` | Show command history |
| `about` | About Glinthaven |

## Supported IOC Types

| Type | Example |
|------|---------|
| IPv4 | `8.8.8.8` |
| IPv6 | `2001:4860:4860::8888` |
| Domain | `evil.example.com` |
| URL | `https://malware.example.com/payload` |
| MD5 | `d41d8cd98f00b204e9800998ecf8427e` |
| SHA-1 | `da39a3ee5e6b4b0d3255bfef95601890afd80709` |
| SHA-256 | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| Email | `attacker@evil.com` |
| CVE | `CVE-2024-1234` |

## API Keys

Glinthaven uses free-tier APIs. Keys are stored in your browser's `localStorage` and only sent to the respective service.

| Service | Free Tier | Sign Up |
|---------|-----------|---------|
| **VirusTotal** | 4 requests/min | [virustotal.com](https://www.virustotal.com/gui/join-us) |
| **AbuseIPDB** | 1,000 checks/day | [abuseipdb.com](https://www.abuseipdb.com/register) |
| **Shodan** | Basic lookups | [shodan.io](https://account.shodan.io/register) |
| **AlienVault OTX** | Unlimited (no key needed) | [otx.alienvault.com](https://otx.alienvault.com/accounts/signup/) |

> **Note:** AlienVault OTX works without an API key, so you can start searching immediately.

## Deploying with Docker

Running Glinthaven via Docker is highly recommended to circumvent any browser CORS restrictions. The Docker setup automatically runs the backend caching proxy and serves the frontend.

### Option 1: Quick Deployment (Pre-built Image)
You can instantly deploy the latest version of Glinthaven directly from the GitHub Container Registry. No source code compilation required!

```bash
# Pull and start the pre-built container from GHCR
docker run -p 8000:3000 -d ghcr.io/edgevolt/glinthaven:latest
```
Then launch http://localhost:8000 in your browser.

### Option 2: Build from Source Local Setup
If you plan to modify the code or prefer to build the container yourself:

```bash
# Using docker-compose (easiest):
docker compose up -d --build

# Or using plain Docker:
docker build -t glinthaven .
docker run -p 8000:3000 -d glinthaven
```
Then launch http://localhost:8000.

### Local Node Production
```bash
npm run build     # Build the frontend to dist/
npm start         # Run the proxy serving the frontend
```

## Project Structure

```
glinthaven/
├── index.html              # Entry point
├── CONTRIBUTING.md         # How to add new sources
├── public/
│   └── favicon.svg         # App icon
└── src/
    ├── main.js             # App init, view routing, keyboard shortcuts
    ├── index.css           # Design system (dark terminal theme)
    ├── terminal.js         # CLI component (input, history, commands)
    ├── ioc-detector.js     # Regex-based IOC type detection
    ├── source-registry.js  # Plugin registry (add new sources here)
    ├── api-client.js       # Query orchestrator (uses registry)
    ├── results-renderer.js # Terminal-styled result formatting
    ├── settings.js         # API key management (auto from registry)
    ├── help.js             # Built-in help system
    └── sources/            # One file per threat intel source
        ├── virustotal.js
        ├── abuseipdb.js
        ├── shodan.js
        └── otx.js
```

## Contributing

Want to add a new threat intel source? See [CONTRIBUTING.md](CONTRIBUTING.md) for the plugin interface and step-by-step instructions. It's designed to be easy — create one file, register it, done.

## License

MIT
