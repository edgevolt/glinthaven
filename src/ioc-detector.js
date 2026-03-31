/**
 * IOC Detector — Identifies the type of Indicator of Compromise from user input.
 */

const IOC_PATTERNS = [
  {
    type: 'ipv4',
    label: 'IPv4 Address',
    regex: /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$/,
  },
  {
    type: 'ipv6',
    label: 'IPv6 Address',
    regex: /^(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}$|^::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){1,6}:$/,
  },
  {
    type: 'cve',
    label: 'CVE ID',
    regex: /^CVE-\d{4}-\d{4,}$/i,
  },
  {
    type: 'asn',
    label: 'Autonomous System (AS)',
    regex: /^AS\d+$/i,
    transform: (raw) => raw.toUpperCase(),
  },
  {
    type: 'sha256',
    label: 'SHA-256 Hash',
    regex: /^[0-9a-fA-F]{64}$/,
  },
  {
    type: 'sha1',
    label: 'SHA-1 Hash',
    regex: /^[0-9a-fA-F]{40}$/,
  },
  {
    type: 'md5',
    label: 'MD5 Hash',
    regex: /^[0-9a-fA-F]{32}$/,
  },
  {
    type: 'url',
    label: 'URL',
    regex: /^https?:\/\/.+/i,
  },
  {
    type: 'email',
    label: 'Email Address',
    regex: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
  },
  {
    type: 'mac',
    label: 'MAC Address (BSSID)',
    // Accepts colon, hyphen, or dot-delimited MAC — 6 groups of 2 hex digits
    regex: /^([0-9a-fA-F]{2}[:\-.]){5}[0-9a-fA-F]{2}$|^[0-9a-fA-F]{12}$|^([0-9a-fA-F]{4}\.){2}[0-9a-fA-F]{4}$/,
  },
  {
    type: 'ssid',
    label: 'WiFi Network Name (SSID)',
    // Must start with "ssid:" prefix to avoid ambiguity with other string types
    regex: /^ssid:.+$/i,
    transform: (raw) => raw.replace(/^ssid:/i, '').trim(),
  },
  {
    type: 'domain',
    label: 'Domain',
    regex: /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/,
  },
];

/**
 * Detect the IOC type from raw input.
 * @param {string} input — raw user input
 * @returns {{ type: string, label: string, value: string } | null}
 */
export function detectIOC(input) {
  const trimmed = input.trim();
  if (!trimmed) return null;

  for (const pattern of IOC_PATTERNS) {
    if (pattern.regex.test(trimmed)) {
      return {
        type: pattern.type,
        label: pattern.label,
        value: pattern.transform ? pattern.transform(trimmed) : trimmed,
      };
    }
  }
  return null;
}

/**
 * Get a friendly description of all supported IOC types.
 */
export function getSupportedTypes() {
  return IOC_PATTERNS.map(p => ({ type: p.type, label: p.label }));
}
