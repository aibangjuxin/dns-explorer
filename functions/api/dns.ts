/// <reference types="@cloudflare/workers-types" />

interface DnsAnswer {
  name: string;
  type: number;
  TTL: number;
  data: string;
}

interface DoHResponse {
  Status: number;
  TC: boolean;
  RD: boolean;
  RA: boolean;
  AD: boolean;
  CD: boolean;
  Question: { name: string; type: number }[];
  Answer?: DnsAnswer[];
}

interface PagesContext {
  request: Request;
  env: { ASSETS?: Fetcher };
}

type PagesFunction = (ctx: PagesContext) => Promise<Response> | Response;

const DOH_ENDPOINTS: Record<string, string> = {
  cloudflare: 'https://cloudflare-dns.com/dns-query',
  cloudflare2: 'https://cloudflare-dns.com/dns-query',
  google: 'https://dns.google/resolve',
  google2: 'https://dns.google/resolve',
  quad9: 'https://dns.quad9.net/dns-query',
  quad9_secondary: 'https://dns.quad9.net/dns-query',
  opendns: 'https://doh.opendns.com/dns-query',
  adguard: 'https://dns.adguard-dns.com/dns-query',
  adguard_family: 'https://family.adguard-dns.com/dns-query',
  nextdns: 'https://dns.nextdns.io/dns-query',
  mullvad: 'https://adblock.dns.mullvad.net/dns-query',
  dnssb: 'https://doh.dns.sb/dns-query',
  dnspod: 'https://doh.pub/dns-query',
  alidns: 'https://dns.alidns.com/resolve',
  q360: 'https://doh.360.cn/dns-query',
};

const CORS_HEADERS: Record<string, string> = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

export const onRequestOptions: PagesFunction = async () => {
  return new Response(null, { headers: CORS_HEADERS });
};

export const onRequestGet: PagesFunction = async ({ request }) => {
  const url = new URL(request.url);
  const domain = url.searchParams.get('domain');
  const type = (url.searchParams.get('type') || 'A').toUpperCase();
  const serverKey = (url.searchParams.get('server') || 'cloudflare').toLowerCase();

  if (!domain) {
    return jsonResponse({ error: 'domain parameter required' }, 400);
  }

  const endpoint = DOH_ENDPOINTS[serverKey];
  if (!endpoint) {
    return jsonResponse(
      { error: `unknown dns server: ${serverKey}. use: ${Object.keys(DOH_ENDPOINTS).join(', ')}` },
      400,
    );
  }

  const dohUrl = `${endpoint}?name=${encodeURIComponent(domain)}&type=${type}`;

  try {
    const dohResp = await fetch(dohUrl, {
      headers: { Accept: 'application/dns-json' },
    });

    if (!dohResp.ok) {
      return jsonResponse({ error: `DoH backend returned HTTP ${dohResp.status}` }, 502);
    }

    const dohData = (await dohResp.json()) as DoHResponse;
    const ips = extractIps(dohData);
    const edge = request.cf?.colo;

    return jsonResponse({
      domain,
      recordType: type,
      dnsServer: serverKey,
      verdict: classifyVerdict(ips),
      ips,
      rcode: dohData.Status,
      raw: dohData,
      timestamp: new Date().toISOString(),
      edge: edge ?? 'unknown',
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return jsonResponse({ error: `DoH fetch failed: ${message}` }, 500);
  }
};

function extractIps(doh: DoHResponse): Array<{ ip: string; type: string; ttl: number; ipClass: string }> {
  if (!doh.Answer) return [];
  return doh.Answer.filter((a) => a.type === 1 || a.type === 28).map((a) => ({
    ip: a.data,
    type: a.type === 28 ? 'AAAA' : 'A',
    ttl: a.TTL,
    ipClass: classifyIp(a.data),
  }));
}

function classifyIp(ip: string): string {
  if (/^10\./.test(ip)) return 'private';
  if (/^192\.168\./.test(ip)) return 'private';
  if (/^172\.(1[6-9]|2[0-9]|3[01])\./.test(ip)) return 'private';
  if (/^127\./.test(ip)) return 'localhost';
  if (/^169\.254\./.test(ip)) return 'link-local';
  if (/^100\.(6[4-9]|[7-9]\d|1[0-1]\d|12[0-7])\./.test(ip)) return 'cgnat';
  if (/^fc00:/i.test(ip) || /^fd[0-9a-f]{2}:/i.test(ip)) return 'private';
  if (/^fe80:/i.test(ip)) return 'link-local';
  if (/^::1$/.test(ip)) return 'localhost';
  return 'public';
}

function classifyVerdict(ips: { ipClass: string }[]): string {
  if (ips.length === 0) return 'NXDOMAIN';
  const classes = new Set(ips.map((i) => i.ipClass));
  if (classes.size === 1) {
    const first = classes.values().next().value;
    return first ?? 'unknown';
  }
  if (classes.has('public')) return 'mixed';
  return Array.from(classes).sort().join('+');
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      ...CORS_HEADERS,
    },
  });
}
