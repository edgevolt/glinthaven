import express from 'express';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';

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

// Serve frontend in production
app.use(express.static(path.join(__dirname, 'dist')));
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'dist', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Backend proxy running on http://localhost:${PORT}`);
});
