# Contributing to Glinthaven

Thanks for your interest in contributing! Glinthaven uses a **plugin-based architecture** that makes it straightforward to add new threat intelligence sources.

## Adding a New Source

This is the most common contribution. Each source is a self-contained module — you create one file and register it.

### Step 1: Create the Source Module

Create a new file at `src/sources/your-source.js`:

```js
/**
 * Your Source Name
 * https://your-service.com
 *
 * Supports: IPv4, domain, etc.
 * Requires: free API key
 */

/** @type {import('../source-registry.js').Source} */
export default {
  // Unique ID — used as the localStorage key for the API key
  id: 'your-source',

  // Human-readable name shown in results and settings
  name: 'Your Source',

  // Which IOC types this source can handle
  // Options: 'ipv4', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256', 'email', 'cve'
  supportedTypes: ['ipv4', 'domain'],

  // If true, the user must configure an API key before queries work
  requiresKey: true,

  // Where users can sign up for a free API key
  signupUrl: 'https://your-service.com/signup',

  // Human-readable rate limit info shown in the settings panel
  rateLimit: '100 requests/day',

  // The query function — called with the IOC and the user's API key
  async query(ioc, apiKey) {
    const res = await fetch(`https://api.your-service.com/lookup/${ioc.value}`, {
      headers: { 'Authorization': `Bearer ${apiKey}` },
    });

    if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);

    const json = await res.json();

    // Return a normalized result (see "Result Format" below)
    return {
      severity: 'low',
      fields: [
        { key: 'Risk Score', value: `${json.score}/100`, severity: 'good' },
        { key: 'Category', value: json.category },
      ],
      tags: ['clean'],
    };
  },
};
```

### Step 2: Register the Source

Open `src/source-registry.js` and:

1. Import your module:
   ```js
   import yourSource from './sources/your-source.js';
   ```

2. Add it to the `sources` array:
   ```js
   const sources = [
     virustotal,
     abuseipdb,
     shodan,
     otx,
     yourSource,  // ← add here
   ];
   ```

That's it. The settings panel, API key management, and query routing all pick up the new source automatically.

### Step 3: Test

```bash
npm run dev
# Open http://localhost:5173/?t
# Type "settings" → verify your source appears
# Search an IOC of a supported type → verify results render
```

---

## Result Format

The `query()` function must return an object matching this shape:

```js
{
  // Overall threat severity — controls the left border color of the result block
  severity: 'info' | 'low' | 'medium' | 'high',

  // Key-value pairs to display in the result block
  fields: [
    {
      key: 'Field Name',          // Left column label
      value: 'Field Value',       // Right column value
      severity: 'good' | 'warn' | 'danger' | 'neutral',  // Optional, colors the value
    },
  ],

  // Optional tags shown as badges below the fields
  tags: ['malicious', 'phishing'],
}
```

**Severity → color mapping:**
| Severity | Border | Meaning |
|----------|--------|---------|
| `info`   | Cyan   | No data or neutral |
| `low`    | Green  | Low risk, probably clean |
| `medium` | Amber  | Some concerns |
| `high`   | Red    | Threats detected |

**Field severity → text color:**
| Value | Color | Use for |
|-------|-------|---------|
| `good`    | Green | Clean results, low scores |
| `warn`    | Amber | Moderate concerns |
| `danger`  | Red   | Malicious, high scores |
| `neutral` | Gray  | Informational |

**Tag styling** is automatic based on keywords (`malicious` → red, `tor` → amber, `clean` → green, etc.)

---

## Error Handling

If something goes wrong in your `query()` function:
- **Throw an error** with a descriptive message — the framework catches it and renders it cleanly
- For "not found" results, return a normal result with `severity: 'info'` instead of throwing
- The API key is checked before `query()` is called for sources with `requiresKey: true`

---

## Project Structure

```
src/
├── main.js              # App init and view routing
├── terminal.js          # CLI interface
├── ioc-detector.js      # IOC type detection (regex)
├── source-registry.js   # ← Source plugin registry
├── api-client.js        # Query orchestrator (uses registry)
├── results-renderer.js  # Terminal output formatting
├── settings.js          # API key management (uses registry)
├── help.js              # Help system
├── index.css            # Design system
└── sources/             # ← One file per source
    ├── virustotal.js
    ├── abuseipdb.js
    ├── shodan.js
    └── otx.js
```

---

## Development

```bash
npm install          # Install dependencies
npm run dev          # Start dev server (localhost:5173)
npm run build        # Production build → dist/
npm run preview      # Preview production build
```

## Code Style

- Vanilla JavaScript (no framework, no TypeScript)
- ES Modules (`import`/`export`)
- Descriptive JSDoc comments on exported functions
- Error messages should be actionable (tell the user what to do)
