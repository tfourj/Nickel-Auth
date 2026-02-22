import rateLimit, { ipKeyGenerator } from 'express-rate-limit';
import axios from 'axios';
import fs from 'fs';
import net from 'node:net';
import { authCache } from './server.js';

const maxLimitReq = parseInt(process.env.RATE_LIMIT) || 50;
const bannedIpsFile = './banned-ips.log';
const trustedProxyCidrsRaw = String(process.env.TRUSTED_PROXY_CIDRS || '').trim();
const useCloudflareIps = String(process.env.USE_CLOUDFLARE_IPS || 'false').toLowerCase() === 'true';
const cloudflareIpv4Url = process.env.CLOUDFLARE_IPV4_URL || 'https://www.cloudflare.com/ips-v4';
const cloudflareIpv6Url = process.env.CLOUDFLARE_IPV6_URL || 'https://www.cloudflare.com/ips-v6';
let trustedProxyAllowlist = new net.BlockList();
let trustedProxyCidrs = [];
let trustedProxyInitialized = false;

function sanitizeIpValue(value) {
  if (typeof value !== 'string') return '';
  let cleaned = value.replace(/[\r\n\t]/g, '').trim();
  if (!cleaned) return '';
  if (cleaned.startsWith('::ffff:')) {
    cleaned = cleaned.slice(7);
  }
  if (cleaned.startsWith('[') && cleaned.endsWith(']')) {
    cleaned = cleaned.slice(1, -1);
  }
  if (!cleaned) return '';
  return net.isIP(cleaned) ? cleaned : '';
}

function parseCidrs(raw) {
  if (!raw || typeof raw !== 'string') return [];
  return raw
    .split(/[\s,]+/)
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function applyTrustedProxyCidrs(entries, sourceLabel) {
  trustedProxyAllowlist = new net.BlockList();
  trustedProxyCidrs = [];
  const deduped = new Set(entries);

  for (const rule of deduped) {
    const [address, prefix] = rule.split('/');
    const sanitizedAddress = sanitizeIpValue(address);
    const prefixNum = Number(prefix);
    const ipVersion = net.isIP(sanitizedAddress);
    const maxPrefix = ipVersion === 4 ? 32 : 128;

    if (
      !sanitizedAddress ||
      Number.isNaN(prefixNum) ||
      !Number.isInteger(prefixNum) ||
      !ipVersion ||
      prefixNum < 0 ||
      prefixNum > maxPrefix
    ) {
      console.warn(`Skipping invalid trusted proxy CIDR from ${sourceLabel}: ${rule}`);
      continue;
    }

    const type = ipVersion === 4 ? 'ipv4' : 'ipv6';
    trustedProxyAllowlist.addSubnet(sanitizedAddress, prefixNum, type);
    trustedProxyCidrs.push(`${sanitizedAddress}/${prefixNum}`);
  }

  return trustedProxyCidrs;
}

function logTrustedProxyCidrs(sourceLabel) {
  if (!trustedProxyCidrs.length) {
    console.warn('No trusted proxy CIDRs configured; forwarded headers will be ignored.');
    return;
  }

  console.log(`Trusted proxy CIDRs loaded from ${sourceLabel} (${trustedProxyCidrs.length}):`);
  trustedProxyCidrs.forEach((cidr) => console.log(` - ${cidr}`));
}

export async function initializeTrustedProxyCidrs() {
  if (trustedProxyInitialized) return trustedProxyCidrs;
  trustedProxyInitialized = true;
  const manualCidrs = parseCidrs(trustedProxyCidrsRaw);

  if (useCloudflareIps) {
    try {
      const [ipv4Res, ipv6Res] = await Promise.all([
        axios.get(cloudflareIpv4Url, { timeout: 5000, responseType: 'text' }),
        axios.get(cloudflareIpv6Url, { timeout: 5000, responseType: 'text' })
      ]);
      const cloudflareCidrs = [...parseCidrs(ipv4Res.data), ...parseCidrs(ipv6Res.data)];
      const combinedCidrs = [...cloudflareCidrs, ...manualCidrs];
      applyTrustedProxyCidrs(combinedCidrs, 'Cloudflare + TRUSTED_PROXY_CIDRS');
      logTrustedProxyCidrs('Cloudflare + TRUSTED_PROXY_CIDRS');
      return trustedProxyCidrs;
    } catch (error) {
      console.error(`Failed to fetch Cloudflare IP ranges: ${error.message}`);
      console.warn('Falling back to TRUSTED_PROXY_CIDRS.');
    }
  }

  applyTrustedProxyCidrs(manualCidrs, 'TRUSTED_PROXY_CIDRS');
  logTrustedProxyCidrs('TRUSTED_PROXY_CIDRS');
  return trustedProxyCidrs;
}

function isTrustedProxyIp(ip) {
  if (!trustedProxyCidrs.length) return false;
  const sanitizedIp = sanitizeIpValue(ip);
  if (!sanitizedIp) return false;
  const type = net.isIP(sanitizedIp) === 4 ? 'ipv4' : 'ipv6';
  return trustedProxyAllowlist.check(sanitizedIp, type);
}

export function addIpToBannedList(ip) {
  try {
    const sanitizedIp = sanitizeIpValue(ip);
    if (!sanitizedIp) return;

    if (!fs.existsSync(bannedIpsFile)) {
      console.error(`Banned IPs file does not exist. Please create it manually...`);
    }
    const bannedList = fs.readFileSync(bannedIpsFile, 'utf8').split('\n').map(line => line.trim());
    if (bannedList.includes(sanitizedIp)) {
      return;
    }
    fs.appendFileSync(bannedIpsFile, `${sanitizedIp}\n`, 'utf8');
    console.error(`Blacklisted IP due to rate limit: ${sanitizedIp}`);
  } catch (err) {
    console.error(`Failed to write IP ${ip} to banned list:`, err.message);
  }
}

export function getClientIp(req) {
  const peerIp = sanitizeIpValue(req.socket?.remoteAddress);
  const trustForwardedHeaders = isTrustedProxyIp(peerIp);

  if (trustForwardedHeaders) {
    const cfConnectingIp = req.headers['cf-connecting-ip'];
    if (cfConnectingIp) {
      const ip = sanitizeIpValue(String(cfConnectingIp).split(',')[0]);
      if (ip) return ip;
    }

    if (useCloudflareIps) {
      return sanitizeIpValue(req.ip) || peerIp || 'unknown';
    }

    const forwardedFor = req.headers['x-forwarded-for'];
    if (forwardedFor) {
      const ip = sanitizeIpValue(String(forwardedFor).split(',')[0]);
      if (ip) return ip;
    }
  }

  return sanitizeIpValue(req.ip) || peerIp || 'unknown';
}

function getRateLimitKey(req) {
  const ip = getClientIp(req);
  return ipKeyGenerator(ip || 'unknown');
}

// Main rate limiter for all requests
export const limiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: maxLimitReq,
  message: 'Too many requests from this IP, please try again later.',
  headers: true,
  keyGenerator: getRateLimitKey,
  handler: (req, res, next) => {
    const ip = getClientIp(req);
    addIpToBannedList(ip);
    res.status(429).send('Too many requests from this IP, please try again later.');
  },
});

// Challenge-specific rate limiter
export const challengeLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 5, 
  message: 'Too many challenge requests, please try again later.',
  standardHeaders: true,
  keyGenerator: getRateLimitKey
});

// Input validation function
export function validateInput(input, type = 'string') {
  if (type === 'string' && (typeof input !== 'string' || input.trim() === '')) {
    throw new Error('Invalid input: Expected a non-empty string.');
  }
  if (type === 'object' && (typeof input !== 'object' || input === null)) {
    throw new Error('Invalid input: Expected a valid object.');
  }
  return input;
}

// Updated to accept apiKeys as parameter
export function loadApiKeys(apiKeysObj) {
  try {
    const raw = fs.readFileSync('./api_keys.json');
    const rawKeys = JSON.parse(raw);
    const normalizeUrl = (url) => (typeof url === 'string' ? url.replace(/\/+$/, '') : url);
    
    // Clear the existing keys
    Object.keys(apiKeysObj).forEach(key => delete apiKeysObj[key]);
    
    // Normalize keys by removing trailing slashes
    Object.entries(rawKeys).forEach(([key, value]) => {
      const normalizedKey = normalizeUrl(key);

      if (typeof value === 'string') {
        apiKeysObj[normalizedKey] = value;
        return;
      }

      if (value && typeof value === 'object') {
        if (Array.isArray(value.servers)) {
          const servers = value.servers
            .map((server) => {
              if (typeof server === 'string') {
                return {
                  url: normalizeUrl(server),
                  key: typeof value.key === 'string' ? value.key : undefined
                };
              }
              if (server && typeof server === 'object') {
                return {
                  url: normalizeUrl(server.url),
                  key: typeof server.key === 'string'
                    ? server.key
                    : (typeof value.key === 'string' ? value.key : undefined)
                };
              }
              return null;
            })
            .filter((entry) => entry && entry.url && entry.key);

          if (servers.length > 0) {
            apiKeysObj[normalizedKey] = { servers };
            return;
          }
        } else if (value.servers && typeof value.servers === 'object') {
          const servers = Object.entries(value.servers)
            .filter(([serverUrl]) => typeof serverUrl === 'string' && serverUrl.trim() !== '')
            .map(([serverUrl, serverKey]) => ({
              url: normalizeUrl(serverUrl),
              key: typeof serverKey === 'string'
                ? serverKey
                : (typeof value.key === 'string' ? value.key : undefined)
            }))
            .filter((entry) => entry.url && entry.key);

          if (servers.length > 0) {
            apiKeysObj[normalizedKey] = { servers };
            return;
          }
        }

        if (typeof value.key === 'string') {
          apiKeysObj[normalizedKey] = value.key;
          return;
        }
      }

      console.log(`Skipping invalid api_keys.json entry: ${key}`);
    });
    
    console.log('🔁 Reloaded API keys');
  } catch (err) {
    console.error('❌ Failed to load api_keys.json:', err.message);
  }
}

export async function validateDeviceToken(deviceToken) {
  if (!deviceToken || typeof deviceToken !== 'string') {
    console.error('Invalid device token (validateDeviceToken).');
    return false;
  }

  if (authCache.has(deviceToken)) return true;

  console.error('Device token validation failed (validateDeviceToken).');
  return false;
}

export function extractDomain(url) {
  try {
    if (!url || typeof url !== 'string') return 'unknown';
    const cleanUrl = url.replace(/^https?:\/\//, '');
    const domain = cleanUrl.split('/')[0];
    return domain || 'unknown';
  } catch {
    return 'unknown';
  }
}
