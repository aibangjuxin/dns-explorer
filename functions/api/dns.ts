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

interface ExtractedRecord {
  data: string;
  type: string;
  ttl: number;
  ipClass?: string;
}

interface ExtractedRecords {
  ips: ExtractedRecord[];
  aliases: ExtractedRecord[];
  texts: ExtractedRecord[];
  mx: ExtractedRecord[];
  other: ExtractedRecord[];
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
    const records = extractRecords(dohData);
    const edge = request.cf?.colo;

    return jsonResponse({
      domain,
      recordType: type,
      dnsServer: serverKey,
      verdict: classifyVerdict(dohData.Status, records),
      ips: records.ips,
      aliases: records.aliases,
      mx: records.mx,
      texts: records.texts,
      other: records.other,
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

// IANA DNS RR type numbers we render in the UI
const TYPE_NAME: Record<number, string> = {
  1: 'A',
  2: 'NS',
  5: 'CNAME',
  6: 'SOA',
  12: 'PTR',
  15: 'MX',
  16: 'TXT',
  28: 'AAAA',
  33: 'SRV',
  35: 'NAPTR',
  41: 'OPT',
  43: 'DS',
  46: 'RRSIG',
  47: 'NSEC',
  48: 'DNSKEY',
  257: 'CAA',
};

function extractRecords(doh: DoHResponse): ExtractedRecords {
  const empty: ExtractedRecords = { ips: [], aliases: [], texts: [], mx: [], other: [] };
  if (!doh.Answer) return empty;

  for (const a of doh.Answer) {
    const typeName = TYPE_NAME[a.type] ?? `T${a.type}`;
    const base: ExtractedRecord = { data: a.data, type: typeName, ttl: a.TTL };

    if (a.type === 1 || a.type === 28) {
      empty.ips.push({ ...base, ipClass: classifyIp(a.data) });
    } else if (a.type === 5 || a.type === 2 || a.type === 12 || a.type === 257) {
      // CNAME / NS / PTR / CAA — name references, not IPs
      empty.aliases.push(base);
    } else if (a.type === 16) {
      empty.texts.push(base);
    } else if (a.type === 15) {
      // MX data is "priority target" — keep verbatim; UI splits on first space
      empty.mx.push(base);
    } else {
      // SOA / SRV / DS / DNSSEC etc. — surface in "other" so the raw panel
      // can also reveal them
      empty.other.push(base);
    }
  }
  return empty;
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

function classifyVerdict(rcode: number, rec: ExtractedRecords): string {
  // No answers at all
  if (rec.ips.length === 0 && rec.aliases.length === 0 && rec.texts.length === 0 && rec.mx.length === 0 && rec.other.length === 0) {
    if (rcode === 3) return 'NXDOMAIN';
    if (rcode === 0) return 'NODATA';
    return `RCODE_${rcode}`;
  }

  // If we have IP answers, classify by IP class (existing behavior)
  if (rec.ips.length > 0) {
    const classes = new Set(rec.ips.map((i) => i.ipClass ?? 'unknown'));
    if (classes.size === 1) {
      const first = classes.values().next().value;
      return first ?? 'unknown';
    }
    if (classes.has('public')) return 'mixed';
    return Array.from(classes).sort().join('+');
  }

  // No IP answers, but other record types came back — summarize by type
  const types: string[] = [];
  if (rec.aliases.length > 0) types.push(rec.aliases[0].type);
  if (rec.mx.length > 0) types.push('MX');
  if (rec.texts.length > 0) types.push('TXT');
  if (rec.other.length > 0) types.push(rec.other[0].type);
  return types.join('+') || 'empty';
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
