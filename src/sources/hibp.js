/**
 * Have I Been Pwned Source
 * https://haveibeenpwned.com
 *
 * Supports: email
 */

/** @type {import('../source-registry.js').Source} */
export default {
  id: 'hibp',
  name: 'Have I Been Pwned',
  category: 'Breach & Leaks',
  supportedTypes: ['email'],
  requiresKey: true,
  signupUrl: 'https://haveibeenpwned.com/API/Key',
  rateLimit: '10 requests / min',

  async testAuth(apiKey) {
    // Check against a known breach address to test if the key authorizes
    const res = await fetch(`/api/proxy/hibp/test@example.com`, {
      headers: { 'hibp-api-key': apiKey }
    });
    if (res.status === 401 || res.status === 403) throw new Error('API Key invalid');
    if (!res.ok && res.status !== 404) throw new Error('Could not verify API key');
  },

  async query(ioc, apiKey) {
    const res = await fetch(`/api/proxy/hibp/${encodeURIComponent(ioc.value)}`, {
      headers: { 'hibp-api-key': apiKey }
    });

    if (res.status === 404) {
      return { severity: 'info', fields: [{ key: 'Result', value: 'Clean. No breaches detected.' }], tags: ['clean'] };
    }
    if (res.status === 401) throw new Error('Invalid HIBP API Key');
    if (res.status === 429) throw new Error('HIBP rate limit exceeded');
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);

    const json = await res.json();
    return normalize(json);
  },
};

function normalize(breaches) {
  let severity = 'high';
  const fields = [];
  const tags = [];

  if (!Array.isArray(breaches) || breaches.length === 0) {
    return { severity: 'info', fields: [{ key: 'Result', value: 'Clean. No breaches detected.' }] };
  }

  tags.push('pwned');

  // Sort by BreachDate descending (newest first)
  breaches.sort((a, b) => new Date(b.BreachDate) - new Date(a.BreachDate));

  let isComboListDetected = false;
  let exposedDataTypes = new Set();
  
  breaches.forEach(b => {
    if (b.IsSpamList || b.IsFabricated || /collection[#\s]?\d|antipublic|exploit\.in/i.test(b.Name)) {
      isComboListDetected = true;
    }
    if (Array.isArray(b.DataClasses)) {
      b.DataClasses.forEach(dc => exposedDataTypes.add(dc));
    }
  });

  fields.push({ key: 'Total Breaches', value: breaches.length.toString(), severity: breaches.length > 5 ? 'danger' : 'warn' });
  
  if (isComboListDetected) {
    fields.push({ key: '⚠️ Combo List Detected', value: 'Credentials appeared in mass-scraping database or credential stuffing dump.', severity: 'danger' });
    tags.push('combo-list');
  }

  if (exposedDataTypes.has('Passwords')) {
     tags.push('passwords-exposed');
  }

  // Database indexing — top 5
  const topBreaches = breaches.slice(0, 5);
  topBreaches.forEach((b, index) => {
     let summary = `${b.BreachDate}`;
     if (b.Domain) summary += ` | ${b.Domain}`;
     if (b.DataClasses) summary += `\nExposed: ${b.DataClasses.slice(0,4).join(', ')}${b.DataClasses.length > 4 ? '...' : ''}`;
     fields.push({ key: `Breach: ${b.Name}`, value: summary });
  });

  // Roll up the rest into a comma separated list
  const remaining = breaches.slice(5);
  if (remaining.length > 0) {
      fields.push({ key: `Other Breaches (${remaining.length})`, value: remaining.map(b => b.Name).join(', ') });
  }

  if (exposedDataTypes.size > 0) {
     const types = [...exposedDataTypes];
     const displayTypes = types.length > 8 ? types.slice(0, 8).join(', ') + ' ...' : types.join(', ');
     fields.push({ key: 'Top Data Classes Exposed', value: displayTypes });
  }

  return { severity, fields, tags };
}
