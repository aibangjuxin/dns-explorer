# DNS Explorer

Real-time DNS lookup tool deployed on **Cloudflare Pages**, with **Pages Functions** proxying browser queries to public DoH backends (Cloudflare 1.1.1.1 / Google 8.8.8.8 / Quad9 9.9.9.9).

- **Live demo**: <https://dns.caep.uk>
- **No backend server** — runs entirely on Cloudflare's edge network
- **Sub-100ms** DoH lookups (CF Functions → 1.1.1.1 is an internal hop)
- **IP classification** — public / private / CGNAT / localhost / link-local

## Architecture

```
Browser (https://dns.caep.uk)
   ↓ fetch('/api/dns?domain=...')
Pages Function (Cloudflare Edge Worker)
   ↓ fetch('https://cloudflare-dns.com/dns-query?...')
Cloudflare 1.1.1.1 (or Google/Quad9 DoH)
   ↑
JSON response rendered in browser
```

## Project structure

```
dns-explorer/
├── functions/api/dns.ts        # Pages Function: DoH proxy + IP classifier
├── src/                        # Static assets served by Pages
│   ├── index.html
│   ├── style.css
│   └── app.js
├── wrangler.toml               # CF Pages config
├── tsconfig.json
├── package.json
└── README.md
```

## Local development

Requires Node 18+.

```bash
npm install
npm run dev
# opens http://localhost:8788
```

## Deploy

### Option A: Git integration (recommended)

1. Push this repo to GitHub.
2. Cloudflare Dashboard → **Workers & Pages** → **Create** → **Pages** → **Connect to Git**.
3. Select the repo, set:
   - **Build command**: *(leave empty)*
   - **Build output directory**: `src`
4. Click **Save and Deploy**. First deploy takes ~30s.
5. **Custom domain**: Pages project → **Custom domains** → **Set up a custom domain** → `dns.caep.uk`. CF auto-creates the CNAME.

After setup, every `git push` to `main` triggers a new deployment. Pull requests get their own preview URLs.

### Option B: CLI deploy

```bash
npm run deploy
# output: https://<hash>.dns-explorer.pages.dev
```

## API

`GET /api/dns?domain=...&type=...&server=...`

| Param | Values | Default |
|-------|--------|---------|
| `domain` | any FQDN | *required* |
| `type` | `A` / `AAAA` / `CNAME` / `MX` / `TXT` / `NS` | `A` |
| `server` | `cloudflare` / `google` / `quad9` | `cloudflare` |

Example:

```bash
curl 'https://dns.caep.uk/api/dns?domain=github.com&type=A&server=cloudflare'
```

```json
{
  "domain": "github.com",
  "recordType": "A",
  "dnsServer": "cloudflare",
  "verdict": "public",
  "ips": [
    { "ip": "140.82.121.4", "type": "A", "ttl": 60, "ipClass": "public" }
  ],
  "rcode": 0,
  "edge": "NRT",
  "timestamp": "2026-06-14T11:30:00.000Z"
}
```

## IP classification rules

| Range | Class |
|-------|-------|
| `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` | private |
| `127.0.0.0/8`, `::1` | localhost |
| `169.254.0.0/16`, `fe80::/10` | link-local |
| `100.64.0.0/10` | CGNAT (RFC 6598) |
| `fc00::/7` | private (ULA) |
| *all other routable* | public |

## Why Pages Functions over browser → DoH directly?

- **No CORS surprises** — `google.com/resolve` doesn't return `Access-Control-Allow-Origin`, so direct browser fetch is blocked. Pages Functions returns proper CORS headers.
- **Lower latency** — Functions and 1.1.1.1 are on the same internal network.
- **Hide backend choice** — can swap DoH providers without touching the client.

## License

MIT
