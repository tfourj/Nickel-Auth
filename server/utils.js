import rateLimit, { ipKeyGenerator } from 'express-rate-limit';
import fs from 'fs';
import net from 'node:net';
import { authCache } from './server.js';

const maxLimitReq = parseInt(process.env.RATE_LIMIT) || 50;
const bannedIpsFile = './banned-ips.log';
const trustedProxyCidrsRaw = String(process.env.TRUSTED_PROXY_CIDRS || '').trim();
const trustedProxyAllowlist = new net.BlockList();
let trustedProxyRulesLoaded = false;

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

function loadTrustedProxyRules() {
  if (trustedProxyRulesLoaded) return;
  trustedProxyRulesLoaded = true;
  if (!trustedProxyCidrsRaw) return;

  const rules = trustedProxyCidrsRaw
    .split(/[\s,]+/)
    .map((entry) => entry.trim())
    .filter(Boolean);

  for (const rule of rules) {
    const [address, prefix] = rule.split('/');
    const sanitizedAddress = sanitizeIpValue(address);
    const prefixNum = Number(prefix);
    const ipVersion = net.isIP(sanitizedAddress);

    if (!sanitizedAddress || Number.isNaN(prefixNum) || !Number.isInteger(prefixNum) || !ipVersion) {
      console.warn(`Skipping invalid TRUSTED_PROXY_CIDRS entry: ${rule}`);
      continue;
    }

    const type = ipVersion === 4 ? 'ipv4' : 'ipv6';
    trustedProxyAllowlist.addSubnet(sanitizedAddress, prefixNum, type);
  }
}

function isTrustedProxyIp(ip) {
  loadTrustedProxyRules();
  if (!trustedProxyCidrsRaw) return false;
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
