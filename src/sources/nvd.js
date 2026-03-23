/**
 * NIST NVD (National Vulnerability Database) Source
 * https://nvd.nist.gov
 *
 * Supports: CVE IDs
 * API key optional — works without one, key gives higher rate limits
 * API docs: https://nvd.nist.gov/developers/vulnerabilities
 */

/** @type {import('../source-registry.js').Source} */
export default {
  id: 'nvd',
  name: 'NIST NVD',
  supportedTypes: ['cve'],
  requiresKey: false,
  signupUrl: 'https://nvd.nist.gov/developers/request-an-api-key',
  rateLimit: '5 requests/30s (50 with key)',

  async query(ioc, apiKey) {
    const headers = {};
    if (apiKey) headers['apiKey'] = apiKey;

    const res = await fetch(
      `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(ioc.value)}`,
      { headers }
    );

    if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);

    const json = await res.json();
    return normalize(json, ioc.value);
  },
};

function normalize(json, cveId) {
  const vulns = json.vulnerabilities || [];
  if (vulns.length === 0) {
    return { severity: 'info', fields: [{ key: 'Result', value: `${cveId} not found in NVD` }] };
  }

  const cve = vulns[0].cve || {};
  const descriptions = cve.descriptions || [];
  const enDesc = descriptions.find(d => d.lang === 'en')?.value || 'No description available';

  // Extract CVSS scores — try v3.1 first, then v3.0, then v2.0
  const metrics = cve.metrics || {};
  let cvssScore = null;
  let cvssVector = null;
  let cvssSeverity = null;
  let cvssVersion = null;

  if (metrics.cvssMetricV31?.length) {
    const m = metrics.cvssMetricV31[0].cvssData;
    cvssScore = m.baseScore;
    cvssVector = m.vectorString;
    cvssSeverity = m.baseSeverity;
    cvssVersion = '3.1';
  } else if (metrics.cvssMetricV30?.length) {
    const m = metrics.cvssMetricV30[0].cvssData;
    cvssScore = m.baseScore;
    cvssVector = m.vectorString;
    cvssSeverity = m.baseSeverity;
    cvssVersion = '3.0';
  } else if (metrics.cvssMetricV2?.length) {
    const m = metrics.cvssMetricV2[0].cvssData;
    cvssScore = m.baseScore;
    cvssVector = m.vectorString;
    cvssSeverity = m.baseSeverity || scoreSeverityV2(m.baseScore);
    cvssVersion = '2.0';
  }

  // Determine severity from CVSS
  let severity = 'info';
  if (cvssScore !== null) {
    if (cvssScore >= 9.0) severity = 'high';
    else if (cvssScore >= 7.0) severity = 'high';
    else if (cvssScore >= 4.0) severity = 'medium';
    else severity = 'low';
  }

  const fields = [];

  // CVSS
  if (cvssScore !== null) {
    const scoreColor = cvssScore >= 7.0 ? 'danger' : cvssScore >= 4.0 ? 'warn' : 'good';
    fields.push({ key: `CVSS ${cvssVersion}`, value: `${cvssScore} (${cvssSeverity})`, severity: scoreColor });
    if (cvssVector) fields.push({ key: 'Vector', value: cvssVector });
  }

  // Description (truncated)
  fields.push({ key: 'Description', value: enDesc.length > 300 ? enDesc.slice(0, 300) + '…' : enDesc });

  // Dates
  if (cve.published) fields.push({ key: 'Published', value: formatDate(cve.published) });
  if (cve.lastModified) fields.push({ key: 'Last Modified', value: formatDate(cve.lastModified) });

  // Weaknesses (CWE)
  const weaknesses = cve.weaknesses || [];
  const cwes = weaknesses
    .flatMap(w => w.description || [])
    .filter(d => d.lang === 'en' && d.value !== 'NVD-CWE-noinfo')
    .map(d => d.value);
  if (cwes.length > 0) {
    fields.push({ key: 'CWE', value: cwes.join(', ') });
  }

  // References (top 3)
  const refs = cve.references || [];
  if (refs.length > 0) {
    const topRefs = refs.slice(0, 3).map(r => r.url).join(' ');
    fields.push({ key: 'References', value: topRefs });
  }

  // Tags
  const tags = [];
  if (cvssSeverity) tags.push(cvssSeverity.toLowerCase());
  cwes.forEach(c => tags.push(c));
  const sourceTypes = refs.flatMap(r => r.tags || []).filter(t => t);
  if (sourceTypes.includes('Exploit')) tags.push('exploit');
  if (sourceTypes.includes('Patch')) tags.push('patch');

  return { severity, fields, tags: [...new Set(tags)].slice(0, 8) };
}

function formatDate(isoStr) {
  try {
    return new Date(isoStr).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
  } catch {
    return isoStr;
  }
}

function scoreSeverityV2(score) {
  if (score >= 7.0) return 'HIGH';
  if (score >= 4.0) return 'MEDIUM';
  return 'LOW';
}
