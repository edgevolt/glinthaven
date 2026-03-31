/**
 * Source Registry — Central hub for all threat intelligence source plugins.
 *
 * To add a new source, create a file in src/sources/ that exports a default
 * object matching the Source interface, then import and register it below.
 *
 * @typedef {Object} Source
 * @property {string}   id             - Unique identifier (used as localStorage key)
 * @property {string}   name           - Human-readable name
 * @property {string}   category       - Category for settings UI grouping
 * @property {string[]} supportedTypes - IOC types this source can query
 * @property {boolean}  requiresKey    - Whether an API key is required to query
 * @property {string}   signupUrl      - URL where users can get a free API key
 * @property {string}   rateLimit      - Free tier rate limits (shown in settings UI)
 * @property {function(string): Promise<void>} [testAuth] - Optional function to validate an API key instantly
 * @property {function({type: string, value: string}, string?): Promise<Object>} query - The search function
 *
 * @typedef {Object} Result
 * @property {'info'|'low'|'medium'|'high'} severity - Overall threat severity
 * @property {Array<{key: string, value: string, severity?: string}>} fields - Key-value pairs to display
 * @property {string[]} [tags] - Optional tags (e.g. 'malicious', 'tor', 'phishing')
 */

// ─── Import all sources ──────────────────────────────────────────────
// To add a new source: 1) create src/sources/your-source.js
//                      2) import it here
//                      3) add it to the sources array below
import virustotal from './sources/virustotal.js';
import abuseipdb  from './sources/abuseipdb.js';
import shodan     from './sources/shodan.js';
import otx        from './sources/otx.js';
import nvd        from './sources/nvd.js';
import urlscan    from './sources/urlscan.js';
import wigle      from './sources/wigle.js';
import pulsedive  from './sources/pulsedive.js';
import ipwhois    from './sources/ipwhois.js';
import geoip      from './sources/geoip.js';
import arin       from './sources/arin.js';
import netlas     from './sources/netlas.js';
import hackertarget from './sources/hackertarget.js';
import crtsh        from './sources/crtsh.js';
import securitytrails from './sources/securitytrails.js';
import hibp         from './sources/hibp.js';
import bgpview      from './sources/bgpview.js';

const sources = [
  virustotal,
  abuseipdb,
  shodan,
  otx,
  nvd,
  urlscan,
  wigle,
  pulsedive,
  ipwhois,
  geoip,
  arin,
  netlas,
  hackertarget,
  crtsh,
  securitytrails,
  hibp,
  bgpview,
];

// ─── Validation (dev-time safety) ────────────────────────────────────
const REQUIRED_FIELDS = ['id', 'name', 'category', 'supportedTypes', 'requiresKey', 'signupUrl', 'rateLimit', 'query'];

for (const src of sources) {
  for (const field of REQUIRED_FIELDS) {
    if (!(field in src)) {
      console.error(`[source-registry] Source "${src.name || src.id || '?'}" is missing required field: ${field}`);
    }
  }
  if (typeof src.query !== 'function') {
    console.error(`[source-registry] Source "${src.name}" must export a query() function`);
  }
}

// ─── Public API ──────────────────────────────────────────────────────

/**
 * Get all registered sources.
 * @returns {Source[]}
 */
export function getAllSources() {
  return sources;
}

/**
 * Get sources that support a given IOC type.
 * @param {string} iocType
 * @returns {Source[]}
 */
export function getSourcesForType(iocType) {
  return sources.filter(s => s.supportedTypes.includes(iocType));
}

/**
 * Get a single source by ID.
 * @param {string} id
 * @returns {Source|undefined}
 */
export function getSourceById(id) {
  return sources.find(s => s.id === id);
}
