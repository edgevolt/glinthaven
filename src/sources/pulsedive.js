/**
 * Pulsedive Source
 * https://pulsedive.com
 *
 * Supports: IPv4, IPv6, domain, URL
 * Requires: free API key — get one at https://pulsedive.com/account/
 *
 * Risk levels: none → info, low → low, medium → medium,
 *              high/critical → high, unknown → info
 */

/** @type {import('../source-registry.js').Source} */
export default {
  id: 'pulsedive',
  name: 'Pulsedive',
  category: 'General Threat Intel',
  supportedTypes: ['ipv4', 'ipv6', 'domain', 'url'],
  requiresKey: true,
  signupUrl: 'https://pulsedive.com/account/',
  rateLimit: 'Free tier: 30 req/min (unauthenticated: 10/min)',

  async testAuth(apiKey) {
    const res = await fetch(
      `/api/proxy/pulsedive?indicator=pulsedive.com&key=${encodeURIComponent(apiKey)}`
    );
    if (res.status === 401 || res.status === 403) throw new Error('API key invalid');
    if (!res.ok) throw new Error('Could not verify Pulsedive API key');
  },

  async query(ioc, apiKey) {
    const params = new URLSearchParams({ indicator: ioc.value });
    if (apiKey) params.set('key', apiKey);

    const res = await fetch(`/api/proxy/pulsedive?${params.toString()}`);

    if (res.status === 404) {
      return {
        severity: 'info',
        fields: [{ key: 'Result', value: 'Indicator not found in Pulsedive database' }],
        tags: [],
      };
    }
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);

    const json = await res.json();

    // Pulsedive returns { "error": "..." } on bad indicators
    if (json.error) {
      return {
        severity: 'info',
        fields: [{ key: 'Result', value: json.error }],
        tags: [],
      };
    }

    return normalize(json);
  },
};

// ─── Risk mapping ────────────────────────────────────────────────────
const RISK_SEVERITY = {
  none:     'info',
  unknown:  'info',
  low:      'low',
  medium:   'medium',
  high:     'high',
  critical: 'high',
};

const RISK_BADGE = {
  none:     'good',
  unknown:  undefined,
  low:      undefined,
  medium:   'warn',
  high:     'danger',
  critical: 'danger',
};

function normalize(json) {
  const risk      = (json.risk     || 'unknown').toLowerCase();
  const riskScore = json.risk_score;
  const severity  = RISK_SEVERITY[risk] || 'info';

  const fields = [];

  // Risk
  const riskLabel = riskScore != null
    ? `${capitalize(risk)} (score: ${riskScore})`
    : capitalize(risk);
  fields.push({ key: 'Risk', value: riskLabel, severity: RISK_BADGE[risk] });

  // Indicator metadata
  if (json.type)       fields.push({ key: 'Type',     value: capitalize(json.type) });
  if (json.stamp_seen) fields.push({ key: 'Last Seen', value: formatDate(json.stamp_seen) });
  if (json.stamp_added)fields.push({ key: 'First Added', value: formatDate(json.stamp_added) });

  // Geo / network attributes
  const attr = json.attributes || {};

  if (attr.country)   fields.push({ key: 'Country',      value: attr.country });
  if (attr.asn)       fields.push({ key: 'ASN',          value: attr.asn });
  if (attr.org)       fields.push({ key: 'Organization', value: attr.org });

  const ports = flatList(attr.port);
  if (ports) fields.push({ key: 'Open Ports', value: ports });

  const protocols = flatList(attr.protocol);
  if (protocols) fields.push({ key: 'Protocols', value: protocols });

  const techs = flatList(attr.technology);
  if (techs) fields.push({ key: 'Technology', value: techs });

  // Threats
  const threats = (json.threats || []).map(t => t.name).filter(Boolean);
  if (threats.length) {
    fields.push({
      key: 'Associated Threats',
      value: threats.slice(0, 5).join(', '),
      severity: 'danger',
    });
  }

  // Feeds
  const feeds = (json.feeds || []).map(f => f.name).filter(Boolean);
  if (feeds.length) {
    fields.push({ key: 'Seen In Feeds', value: feeds.slice(0, 5).join(', ') });
  }

  // Risk factors
  const factors = (json.risk_factors || []).map(f => f.description || f.name).filter(Boolean);
  if (factors.length) {
    fields.push({ key: 'Risk Factors', value: factors.slice(0, 4).join('; ') });
  }

  // Tags
  const tags = [];
  if (risk === 'high' || risk === 'critical') tags.push('malicious');
  if (risk === 'medium') tags.push('suspicious');
  if (threats.length) tags.push('threat-associated');
  if (feeds.length) tags.push('blocklisted');

  return { severity, fields, tags };
}

// ─── Helpers ─────────────────────────────────────────────────────────
function capitalize(str) {
  if (!str) return '';
  return str.charAt(0).toUpperCase() + str.slice(1);
}

function flatList(val) {
  if (!val) return '';
  if (Array.isArray(val)) return val.slice(0, 8).join(', ');
  return String(val);
}

function formatDate(isoStr) {
  try {
    return new Date(isoStr).toLocaleDateString(undefined, {
      year: 'numeric', month: 'short', day: 'numeric',
    });
  } catch {
    return isoStr;
  }
}
