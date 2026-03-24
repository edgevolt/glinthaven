/**
 * Help System — Command reference and newcomer-friendly guides.
 */

export function getHelpOutput(topic) {
  const t = (topic || '').trim().toLowerCase();

  switch (t) {
    case '':
    case 'commands':
      return helpCommands();
    case 'ioc':
    case 'iocs':
      return helpIOC();
    case 'start':
    case 'quickstart':
    case 'getting-started':
      return helpQuickStart();
    case 'examples':
      return helpExamples();
    case 'api':
    case 'keys':
      return helpAPI();
    default:
      return `<div class="term-line term-warning">Unknown help topic: "${esc(t)}"</div>
<div class="term-line term-system">Available topics: commands, ioc, start, examples, api</div>`;
  }
}

function helpCommands() {
  return `<div class="term-section">Commands</div>
<table class="term-table">
  <tr><td>search &lt;ioc&gt;</td><td>Look up an IOC across all configured sources</td></tr>
  <tr><td>&lt;ioc&gt;</td><td>Shortcut — just paste an IOC directly to search it</td></tr>
  <tr><td>&lt;ioc&gt; --debug</td><td>Search with debug info (latency, HTTP status, endpoint)</td></tr>
  <tr><td>debug [on|off]</td><td>Toggle persistent debug mode for all searches</td></tr>
  <tr><td>help [topic]</td><td>Show help (topics: commands, ioc, start, examples, api)</td></tr>
  <tr><td>settings</td><td>Open API key settings</td></tr>
  <tr><td>setup</td><td>Launch the Quick Setup Wizard</td></tr>
  <tr><td>lock</td><td>Lock the crypto vault and return to launch screen</td></tr>
  <tr><td>clear</td><td>Clear the terminal</td></tr>
  <tr><td>history</td><td>Show command history</td></tr>
  <tr><td>about</td><td>About Glinthaven</td></tr>
</table>
<div class="term-line term-system" style="margin-top:var(--sp-sm)">Tip: You can paste any IOC directly — no need to type "search" first.</div>`;
}

function helpIOC() {
  return `<div class="term-section">Supported IOC Types</div>
<table class="term-table">
  <tr><td>IPv4</td><td>e.g. 8.8.8.8</td></tr>
  <tr><td>IPv6</td><td>e.g. 2001:4860:4860::8888</td></tr>
  <tr><td>Domain</td><td>e.g. evil.example.com</td></tr>
  <tr><td>URL</td><td>e.g. https://malware.example.com/payload</td></tr>
  <tr><td>MD5 Hash</td><td>32 hex characters</td></tr>
  <tr><td>SHA-1 Hash</td><td>40 hex characters</td></tr>
  <tr><td>SHA-256 Hash</td><td>64 hex characters</td></tr>
  <tr><td>Email</td><td>e.g. attacker@evil.com</td></tr>
  <tr><td>CVE ID</td><td>e.g. CVE-2024-1234</td></tr>
</table>
<div class="term-line term-system" style="margin-top:var(--sp-sm)">Glinthaven auto-detects the type — just paste and press Enter.</div>`;
}

function helpQuickStart() {
  return `<div class="term-section">Quick Start Guide</div>
<div class="term-line"><span style="color:var(--cyan)">1.</span> <strong>Set up API keys</strong> — Type <span style="color:var(--cyan)">settings</span> or click ⚙ to add your free API keys</div>
<div class="term-line"><span style="color:var(--cyan)">2.</span> <strong>Search an IOC</strong> — Paste an IP, domain, hash, URL, email, or CVE and press Enter</div>
<div class="term-line"><span style="color:var(--cyan)">3.</span> <strong>Read the results</strong> — Each source shows detection status, severity, and details</div>
<div class="term-line" style="margin-top:var(--sp-sm)"><span style="color:var(--cyan)">4.</span> <strong>Explore</strong> — Try <span style="color:var(--cyan)">help ioc</span> to see all supported types</div>

<div class="term-line term-system" style="margin-top:var(--sp-md)">Severity colors: <span class="term-tag tag-safe">low risk</span> <span class="term-tag tag-warn">medium</span> <span class="term-tag tag-danger">high risk</span></div>

<div class="term-line term-system" style="margin-top:var(--sp-sm)">Note: AlienVault OTX works without an API key. Other services require free signup.</div>`;
}

function helpExamples() {
  return `<div class="term-section">Example Searches</div>
<div class="term-line"><span style="color:var(--text-muted)">❯</span> <span style="color:var(--cyan)">8.8.8.8</span> <span class="term-system">← look up Google DNS IP</span></div>
<div class="term-line"><span style="color:var(--text-muted)">❯</span> <span style="color:var(--cyan)">evil.example.com</span> <span class="term-system">← check a domain</span></div>
<div class="term-line"><span style="color:var(--text-muted)">❯</span> <span style="color:var(--cyan)">d41d8cd98f00b204e9800998ecf8427e</span> <span class="term-system">← search an MD5 hash</span></div>
<div class="term-line"><span style="color:var(--text-muted)">❯</span> <span style="color:var(--cyan)">CVE-2024-1234</span> <span class="term-system">← look up a CVE</span></div>
<div class="term-line"><span style="color:var(--text-muted)">❯</span> <span style="color:var(--cyan)">search https://suspicious.site/page</span> <span class="term-system">← URL search with command prefix</span></div>
<div class="term-line"><span style="color:var(--text-muted)">❯</span> <span style="color:var(--cyan)">8.8.8.8 --debug</span> <span class="term-system">← search with debug info</span></div>`;
}

function helpAPI() {
  return `<div class="term-section">API Key Info</div>
<div class="term-line">Keys are stored locally in your browser (localStorage). They are never sent anywhere except to the respective API service.</div>
<div class="term-line" style="margin-top:var(--sp-sm)"><strong>Required services:</strong></div>
<table class="term-table">
  <tr><td>VirusTotal</td><td><a href="https://www.virustotal.com/gui/join-us" target="_blank" style="color:var(--cyan-dim)">virustotal.com</a> — 4 req/min free</td></tr>
  <tr><td>AbuseIPDB</td><td><a href="https://www.abuseipdb.com/register" target="_blank" style="color:var(--cyan-dim)">abuseipdb.com</a> — 1000 checks/day free</td></tr>
  <tr><td>Shodan</td><td><a href="https://account.shodan.io/register" target="_blank" style="color:var(--cyan-dim)">shodan.io</a> — free tier</td></tr>
</table>
<div class="term-line" style="margin-top:var(--sp-sm)"><strong>Optional (works without key):</strong></div>
<table class="term-table">
  <tr><td>AlienVault OTX</td><td><a href="https://otx.alienvault.com/accounts/signup/" target="_blank" style="color:var(--cyan-dim)">otx.alienvault.com</a> — free</td></tr>
</table>
<div class="term-line term-system" style="margin-top:var(--sp-sm)">Type <span style="color:var(--cyan)">settings</span> to configure your keys.</div>`;
}

function esc(str) {
  const div = document.createElement('div');
  div.textContent = String(str);
  return div.innerHTML;
}
