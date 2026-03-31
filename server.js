import express from 'express';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import https from 'https';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

async function proxyRequest(endpoint, headers, res) {
  try {
    const response = await fetch(endpoint, { headers });
    const text = await response.text();
    let data;
    try {
      data = JSON.parse(text);
    } catch(e) {
      data = text;
    }
    res.status(response.status).json(data);
  } catch(error) {
    res.status(500).json({ error: error.message });
  }
}

app.get('/api/proxy/virustotal/*', async (req, res) => {
  const endpoint = `https://www.virustotal.com/api/v3/${req.params[0]}`;
  const apiKey = req.headers['x-apikey'];
  await proxyRequest(endpoint, { 'x-apikey': apiKey }, res);
});

app.get('/api/proxy/abuseipdb', async (req, res) => {
  const ip = req.query.ipAddress;
  const endpoint = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose`;
  const apiKey = req.headers['key'];
  await proxyRequest(endpoint, { 'Key': apiKey, 'Accept': 'application/json' }, res);
});

app.get('/api/proxy/shodan/*', async (req, res) => {
  const targetPath = req.params[0];
  const apiKey = req.query.key;
  const endpoint = `https://api.shodan.io/${targetPath}?key=${apiKey}`;
  await proxyRequest(endpoint, {}, res);
});

app.get('/api/proxy/otx/*', async (req, res) => {
  const endpoint = `https://otx.alienvault.com/api/v1/${req.params[0]}`;
  const apiKey = req.headers['x-otx-api-key'];
  const headers = {};
  if (apiKey) headers['X-OTX-API-KEY'] = apiKey;
  await proxyRequest(endpoint, headers, res);
});

app.get('/api/proxy/nvd', async (req, res) => {
  const cveId = req.query.cveId;
  const endpoint = `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${encodeURIComponent(cveId)}`;
  const apiKey = req.headers['apikey'];
  const headers = {};
  if (apiKey) headers['apiKey'] = apiKey;
  await proxyRequest(endpoint, headers, res);
});

app.get('/api/proxy/urlscan', async (req, res) => {
  const q = req.query.q;
  const endpoint = `https://urlscan.io/api/v1/search/?q=${encodeURIComponent(q)}`;
  const apiKey = req.headers['api-key'];
  const headers = {};
  if (apiKey) headers['API-Key'] = apiKey;
  await proxyRequest(endpoint, headers, res);
});

app.get('/api/proxy/pulsedive', async (req, res) => {
  const qs = new URLSearchParams(req.query).toString();
  const endpoint = `https://pulsedive.com/api/info.php?${qs}`;
  await proxyRequest(endpoint, { 'Accept': 'application/json' }, res);
});

app.get('/api/proxy/wigle/*', async (req, res) => {
  const targetPath = req.params[0];
  const qs = new URLSearchParams(req.query).toString();
  const endpoint = `https://api.wigle.net/${targetPath}${qs ? '?' + qs : ''}`;
  const authHeader = req.headers['authorization'];
  const headers = { 'Accept': 'application/json' };
  if (authHeader) headers['Authorization'] = authHeader;
  await proxyRequest(endpoint, headers, res);
});

app.get('/api/proxy/ipwhois/*', (req, res) => {
  const ip = req.params[0];
  const endpoint = `https://ipwho.is/${ip}`;
  
  // Use native https instead of fetch to prevent 'sec-fetch-mode: cors' headers
  // which ipwhois.io blocks on its free tier.
  https.get(endpoint, {
    headers: { 'User-Agent': 'curl/8.0.1', 'Accept': 'application/json' }
  }, (proxyRes) => {
    let data = '';
    proxyRes.on('data', chunk => data += chunk);
    proxyRes.on('end', () => {
      try {
        res.status(proxyRes.statusCode).json(JSON.parse(data));
      } catch (e) {
        res.status(proxyRes.statusCode).json({ error: 'Failed to parse JSON', raw: data });
      }
    });
  }).on('error', (err) => {
    res.status(500).json({ error: err.message });
  });
});

app.get('/api/proxy/geoip/*', async (req, res) => {
  const ip = req.params[0];
  const qs = new URLSearchParams(req.query).toString();
  const endpoint = `http://ip-api.com/json/${ip}${qs ? '?' + qs : ''}`;
  await proxyRequest(endpoint, { 'Accept': 'application/json' }, res);
});

app.get('/api/proxy/arin/*', async (req, res) => {
  const ip = req.params[0];
  const endpoint = `https://rdap.arin.net/registry/ip/${ip}`;
  await proxyRequest(endpoint, { 'Accept': 'application/rdap+json' }, res);
});

app.get('/api/proxy/netlas/*', async (req, res) => {
  const endpoint = `https://app.netlas.io/api/${req.params[0]}`;
  const apiKey = req.headers['x-api-key'];
  const headers = {};
  if (apiKey) headers['X-Api-Key'] = apiKey;
  await proxyRequest(endpoint, headers, res);
});

app.get('/api/proxy/securitytrails/*', async (req, res) => {
  const endpoint = `https://api.securitytrails.com/v1/${req.params[0]}`;
  const apiKey = req.headers['apikey'];
  const headers = { 'Accept': 'application/json' };
  if (apiKey) headers['APIKEY'] = apiKey;
  await proxyRequest(endpoint, headers, res);
});

app.get('/api/proxy/hackertarget/*', async (req, res) => {
  const targetPath = req.params[0];
  const q = req.query.q;
  const endpoint = `https://api.hackertarget.com/${targetPath}/?q=${encodeURIComponent(q)}`;
  await proxyRequest(endpoint, { 'User-Agent': 'curl/7.68.0' }, res);
});

app.get('/api/proxy/crtsh', async (req, res) => {
  const q = req.query.q;
  const endpoint = `https://crt.sh/?q=${encodeURIComponent(q)}&output=json`;
  await proxyRequest(endpoint, { 'Accept': 'application/json' }, res);
});

app.get('/api/proxy/hibp/*', async (req, res) => {
  const account = req.params[0];
  const endpoint = `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(account)}?truncateResponse=false`;
  const apiKey = req.headers['hibp-api-key'];
  const headers = {
    'hibp-api-key': apiKey,
    'user-agent': 'glinthaven'
  };
  await proxyRequest(endpoint, headers, res);
});

app.get('/api/proxy/bgpview/*', async (req, res) => {
  const endpoint = `https://api.bgpview.io/${req.params[0]}`;
  await proxyRequest(endpoint, { 'Accept': 'application/json' }, res);
});

// Serve frontend in production
app.use(express.static(path.join(__dirname, 'dist')));
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'dist', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Backend proxy running on http://localhost:${PORT}`);
});
