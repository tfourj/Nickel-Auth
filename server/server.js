// server.js
import express from 'express';
import axios from 'axios';
import bodyParser from 'body-parser';
import NodeCache from 'node-cache';
import fs from 'fs';
import path from 'path';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import chokidar from 'chokidar';
import { v4 as uuidv4 } from 'uuid';
import { verifyAttestation } from 'node-app-attest';
import xss from 'xss';
import helmet from 'helmet';
import client from 'prom-client';
import cors from 'cors';
import { limiter, challengeLimiter, validateInput, loadApiKeys, validateDeviceToken, extractDomain, getClientIp } from './utils.js';

dotenv.config();

const LOG_LEVELS = {
  log: 1,
  info: 1,
  warn: 2,
  debug: 3
};
const configuredLogLevel = String(process.env.LOG_LEVEL || 'log').toLowerCase();
const logThreshold = LOG_LEVELS[configuredLogLevel] ?? LOG_LEVELS.log;
const baseConsole = {
  log: console.log.bind(console),
  info: (console.info || console.log).bind(console),
  warn: console.warn.bind(console),
  error: console.error.bind(console),
  debug: (console.debug || console.log).bind(console)
};
const shouldLog = (level) => {
  if (level === 'error') return true;
  const rank = LOG_LEVELS[level];
  return typeof rank === 'number' && rank <= logThreshold;
};
console.log = (...args) => {
  if (shouldLog('log')) baseConsole.log(...args);
};
console.info = (...args) => {
  if (shouldLog('info')) baseConsole.info(...args);
};
console.warn = (...args) => {
  if (shouldLog('warn')) baseConsole.warn(...args);
};
console.debug = (...args) => {
  if (shouldLog('debug')) baseConsole.debug(...args);
};

const version = (() => {
  const candidates = [
    path.join(process.cwd(), 'package.json'),
    new URL('./package.json', import.meta.url),
    new URL('../package.json', import.meta.url)
  ];

  for (const candidate of candidates) {
    try {
      if (!fs.existsSync(candidate)) continue;
      const raw = fs.readFileSync(candidate, 'utf8');
      const pkg = JSON.parse(raw);
      if (typeof pkg.version === 'string' && pkg.version.trim() !== '') {
        return pkg.version;
      }
    } catch (err) {
      console.log('Failed to read package.json version:', err.message);
    }
  }

  return 'unknown';
})();

const register = client.register;

const startTime = Date.now();
const uptimeGauge = new client.Gauge({
  name: 'server_uptime_seconds',
  help: 'Server uptime in seconds'
});
register.registerMetric(uptimeGauge);

let requestCount = 0;

const maxLimitReq = parseInt(process.env.RATE_LIMIT) || 50;
const jwtSecret = process.env.JWT_SECRET;
const teamId = process.env.APPLE_TEAM_ID;
const bundleId = process.env.APPLE_BUNDLE_ID;
if (!jwtSecret) {
  throw new Error('JWT_SECRET environment variable is not set.');
}

console.log('Environment Variables:');
Object.entries(process.env).forEach(([key, value]) => {
  if (key === 'JWT_SECRET') {
    console.log(`${key}: ${value ? value.slice(0, 4) + '****' : 'Not Set'}`);
  } else {
    console.log(`${key}: ${value}`);
  }
});
console.log('----------------------------------------');
console.log('Starting server setup...');
console.log('----------------------------------------');

const app = express();
const port = process.env.PORT || 3200;
app.set('trust proxy', true);
const parseIpList = (value) => {
  if (!value || typeof value !== 'string') return new Set();
  return new Set(
    value
      .split(/[\s,]+/)
      .map((entry) => entry.trim())
      .filter(Boolean)
  );
};
const filteredLogIps = parseIpList(process.env.LOG_FILTERED_IPS);
const isLogFilteredIp = (req) => {
  if (!filteredLogIps.size) return false;
  const ip = getClientIp(req);
  return Boolean(ip && filteredLogIps.has(ip));
};
const formatRequestIp = (req) => {
  const ip = getClientIp(req);
  return `ip=${ip && typeof ip === 'string' ? ip : 'unknown'}`;
};
const logWithRequestIp = (level, req, message, ...args) => {
  if (isLogFilteredIp(req)) return;
  const ipLabel = formatRequestIp(req);
  console[level](`${message} (${ipLabel})`, ...args);
};

const challengeTTL = parseInt(process.env.CHALLENGE_CACHE_TTL) || 300;
const authTTL = parseInt(process.env.AUTH_CACHE_TTL) || 600;

export const authCache = new NodeCache({ stdTTL: authTTL }); // 10 minutes
export const challengeCache = new NodeCache({ stdTTL: challengeTTL }); // 5 minutes
export let apiKeys = {};
const serverUsage = new Map();
const healthCacheTtl = parseInt(process.env.LB_HEALTHCHECK_CACHE_TTL) || 10;
const healthCheckTimeoutMs = parseInt(process.env.LB_HEALTHCHECK_TIMEOUT_MS) || 1500;
const healthCheckPath = process.env.LB_HEALTHCHECK_PATH || '/';
const healthCheckMethod = (process.env.LB_HEALTHCHECK_METHOD || 'GET').toUpperCase();
const healthCache = new NodeCache({ stdTTL: healthCacheTtl });

app.use(bodyParser.json());

app.use(helmet());

app.use((req, res, next) => {
  if (req.body) {
    req.body = JSON.parse(xss(JSON.stringify(req.body)));
  }
  next();
});

// Apply the main rate limiter
app.use(limiter);

// Load API keys map
loadApiKeys(apiKeys);

// Watch for changes in api_keys.json
chokidar.watch('./api_keys.json').on('change', () => loadApiKeys(apiKeys));

const versionGauge = new client.Gauge({
  name: 'server_version_info',
  help: 'Server version information',
  labelNames: ['version']
});
register.registerMetric(versionGauge);
versionGauge.labels(version).set(1);

const apiCallCounter = new client.Counter({
  name: 'api_call_total',
  help: 'Total number of API calls (excluding /metrics endpoints)',
});
register.registerMetric(apiCallCounter);

const avgResponseTimeGauge = new client.Gauge({
  name: 'api_avg_response_time_ms',
  help: 'Average response time of API calls in milliseconds'
});
register.registerMetric(avgResponseTimeGauge);
let totalResponseTime = 0;
let responseCount = 0;

// Auth server response time
const avgAuthResponseTimeGauge = new client.Gauge({
  name: 'auth_server_avg_response_time_ms',
  help: 'Average response time for auth server endpoints (ios-auth, ios-validate, ios-challenge) in ms'
});
register.registerMetric(avgAuthResponseTimeGauge);
let totalAuthResponseTime = 0;
let authResponseCount = 0;

// Proxy processing time
const avgProxyResponseTimeGauge = new client.Gauge({
  name: 'proxy_avg_processing_time_ms',
  help: 'Average processing time for proxy endpoint (/ios-request) in ms'
});
register.registerMetric(avgProxyResponseTimeGauge);
let totalProxyResponseTime = 0;
let proxyResponseCount = 0;

// Metrics and API call counter middleware
app.use((req, res, next) => {
  const start = process.hrtime();
  res.on('finish', () => {
    // Only increment if not /metrics and not 404
    if (req.path !== '/metrics' && res.statusCode !== 404) {
      apiCallCounter.inc();
      requestCount++;
      const end = process.hrtime(start);
      const duration = (end[0] * 1e3) + (end[1] / 1e6);
      totalResponseTime += duration;
      responseCount++;
      avgResponseTimeGauge.set(totalResponseTime / responseCount);
    }
  });
  next();
});

// --- AUTH SERVER ENDPOINTS METRICS ---

function trackAuthResponseTime(handler) {
  return async (req, res, next) => {
    const start = process.hrtime();
    // Wrap res.end to ensure we always record time
    const origEnd = res.end;
    res.end = function (...args) {
      const end = process.hrtime(start);
      const duration = (end[0] * 1e3) + (end[1] / 1e6);
      totalAuthResponseTime += duration;
      authResponseCount++;
      avgAuthResponseTimeGauge.set(totalAuthResponseTime / authResponseCount);
      origEnd.apply(res, args);
    };
    return handler(req, res, next);
  };
}

// --- PROXY ENDPOINT METRICS ---

function trackProxyResponseTime(handler) {
  return async (req, res, next) => {
    const start = process.hrtime();
    const origEnd = res.end;
    res.end = function (...args) {
      const end = process.hrtime(start);
      const duration = (end[0] * 1e3) + (end[1] / 1e6);
      totalProxyResponseTime += duration;
      proxyResponseCount++;
      avgProxyResponseTimeGauge.set(totalProxyResponseTime / proxyResponseCount);
      origEnd.apply(res, args);
    };
    return handler(req, res, next);
  };
}

function pickLeastUsedServer(servers) {
  let selected = null;
  let lowest = Infinity;

  for (const server of servers) {
    if (!server || !server.url) continue;
    const count = serverUsage.get(server.url) || 0;
    if (count < lowest) {
      lowest = count;
      selected = server;
    }
  }

  return selected;
}

function sortServersByUsage(servers) {
  return [...servers]
    .filter((server) => server && server.url)
    .sort((a, b) => (serverUsage.get(a.url) || 0) - (serverUsage.get(b.url) || 0));
}

function isJsonStatusError(payload) {
  return Boolean(
    payload &&
    typeof payload === 'object' &&
    !Array.isArray(payload) &&
    typeof payload.status === 'string' &&
    payload.status.toLowerCase() === 'error'
  );
}

async function isServerUp(serverUrl) {
  if (!serverUrl || typeof serverUrl !== 'string') return false;

  const cached = healthCache.get(serverUrl);
  if (typeof cached === 'boolean') return cached;

  try {
    const healthUrl = new URL(healthCheckPath, serverUrl).toString();
    const res = await axios.request({
      method: healthCheckMethod,
      url: healthUrl,
      timeout: healthCheckTimeoutMs,
      validateStatus: () => true
    });
    const up = res.status < 500;
    healthCache.set(serverUrl, up);
    if (!up) {
      console.log(`Health check failed for ${serverUrl} with status ${res.status}`);
    }
    return up;
  } catch (err) {
    console.log(`Health check failed for ${serverUrl}: ${err.message}`);
    healthCache.set(serverUrl, false);
    return false;
  }
}

async function resolveApiTargets(apiUrl, apiEntry) {
  if (typeof apiEntry === 'string') {
    return [{ targetUrl: apiUrl, authKey: apiEntry, balanced: false }];
  }

  if (!apiEntry || typeof apiEntry !== 'object' || !Array.isArray(apiEntry.servers)) {
    throw new Error('API not added to authentication server.');
  }

  const healthChecks = await Promise.all(
    apiEntry.servers.map(async (server) => ({
      server,
      up: await isServerUp(server?.url)
    }))
  );
  const healthyServers = healthChecks.filter((entry) => entry.up).map((entry) => entry.server);
  const selected = pickLeastUsedServer(healthyServers);
  if (!selected || !selected.url) {
    throw new Error('No healthy servers available for this API.');
  }
  const orderedTargets = sortServersByUsage(healthyServers)
    .filter((server) => server.key)
    .map((server) => ({
      targetUrl: server.url,
      authKey: server.key,
      balanced: true
    }));

  if (!orderedTargets.length) {
    throw new Error('Missing API key for selected server.');
  }

  return orderedTargets;
}

// --- ENDPOINTS ---

app.get('/ios-challenge', challengeLimiter, trackAuthResponseTime((req, res) => {
    const challenge = uuidv4();
    challengeCache.set(challenge, true);
    logWithRequestIp('log', req, `Challenge was requested, returning ${challenge}`);
    res.send(JSON.stringify({ challenge }));
}));

app.post('/ios-auth', trackAuthResponseTime(async (req, res) => {
  logWithRequestIp('log', req, 'Auth request received');
  try {
    const { attestation, challenge, keyId } = req.body;

    // Validate inputs
    validateInput(attestation);
    validateInput(challenge);
    validateInput(keyId);

    const [hasChallenge] = await Promise.all([
      challengeCache.has(challenge)
    ]);

    if (!challenge || !hasChallenge) {
      return res.status(400).json({ error: "Invalid or expired challenge." });
    }

    await challengeCache.del(challenge);

    logWithRequestIp(
      'log',
      req,
      `Validating attestation - Challenge: ${challenge.substring(0, 8)}..., KeyId: ${keyId.substring(0, 8)}..., Attestation: ${attestation.substring(0, 16)}...`
    );
    
    const result = await Promise.resolve(verifyAttestation({
      attestation: Buffer.from(attestation, 'base64'),
      challenge,
      keyId,
      bundleIdentifier: bundleId,
      teamIdentifier: teamId,
      allowDevelopmentEnvironment: process.env.NODE_ENV !== 'production',
    }));

    logWithRequestIp('log', req, 'Attestation validated successfully');

    const tempKey = await new Promise((resolve, reject) => {
      jwt.sign(
        { keyId, exp: Math.floor(Date.now() / 1000) + authTTL },
        jwtSecret,
        (err, token) => {
          if (err) reject(err);
          else resolve(token);
        }
      );
    });

    await authCache.set(tempKey, result.publicKey);

    res.status(200).json({ tempKey });
  } catch (error) {
    logWithRequestIp('error', req, 'Error in /ios-auth:', error.message);
    res.status(400).json({ error: error.message });
  }
}));

app.post('/ios-request', trackProxyResponseTime(async (req, res) => {
  try {
    const authHeader = req.headers['authorization'] || '';
    const [authType, authToken] = authHeader.split(' ');

    if (authType !== 'Nickel-Auth' || !authToken) {
      throw new Error('Invalid or missing authorization.');
    }

    const valid = await validateDeviceToken(authToken);
    if (!valid) {
      throw new Error('Device not authorized.');
    }

    const body = req.body;
    const { 'api-url': apiUrl, ...filteredBody } = body;

    const userUrl = body.url;
    const domain = userUrl ? extractDomain(userUrl) : 'no-url';

    // Validate API URL
    validateInput(apiUrl);
    
    // Normalize the URL by removing trailing slash
    const normalizedUrl = apiUrl.replace(/\/+$/, '');
    
    const apiEntry = apiKeys[normalizedUrl];
    if (!apiEntry) {
      throw new Error('API not added to authentication server.');
    }

    const targets = await resolveApiTargets(normalizedUrl, apiEntry);
    let lastServerResponse = null;

    for (let index = 0; index < targets.length; index++) {
      const { targetUrl, authKey, balanced } = targets[index];
      const hasNextTarget = index < targets.length - 1;
      serverUsage.set(targetUrl, (serverUsage.get(targetUrl) || 0) + 1);

      if (balanced) {
        logWithRequestIp('log', req, `Load balancing ${normalizedUrl} -> ${targetUrl}`);
      }
      logWithRequestIp('log', req, `Making request to Cobalt API for: ${domain} to instance url: ${targetUrl}`);

      try {
        const cobaltRes = await axios.post(targetUrl, filteredBody, {
          headers: {
            Authorization: `Api-Key ${authKey}`,
            Accept: 'application/json',
          },
        });

        if (isJsonStatusError(cobaltRes.data) && hasNextTarget) {
          logWithRequestIp('warn', req, `Server ${targetUrl} returned JSON status=error, trying next server`);
          lastServerResponse = { status: cobaltRes.status, data: cobaltRes.data };
          continue;
        }

        return res.status(cobaltRes.status).json(cobaltRes.data);
      } catch (err) {
        if (err.response && isJsonStatusError(err.response.data) && hasNextTarget) {
          logWithRequestIp('warn', req, `Server ${targetUrl} returned JSON status=error, trying next server`);
          lastServerResponse = { status: err.response.status, data: err.response.data };
          continue;
        }
        throw err;
      }
    }

    if (lastServerResponse) {
      return res.status(lastServerResponse.status).json(lastServerResponse.data);
    }
    throw new Error('No server response available.');
  } catch (err) {
    if (err.response) {
      logWithRequestIp('error', req, 'Error in /ios-request:', err.response.data);
      res.status(err.response.status).json(err.response.data);
    } else {
      logWithRequestIp('error', req, 'Error in /ios-request:', err.message);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
}));

app.post('/ios-validate', trackAuthResponseTime(async (req, res) => {
  const authHeader = req.headers['authorization'] || '';
  const [authType, authKey] = authHeader.split(' ');
  logWithRequestIp('log', req, `Validating device token: ${authKey.substring(0, 8)}...`);

  if (authType !== 'Nickel-Auth' || !authKey) {
    return res.status(400).json({ error: 'Invalid or missing authorization header.' });
  }

  try {
    const [hasAuth] = await Promise.all([
      authCache.has(authKey)
    ]);

    if (hasAuth) {
      return res.status(200).json({ valid: true });
    } else {
      logWithRequestIp('log', req, `Device token validation failed - not found in cache: ${authKey.substring(0, 8)}...`);
      return res.status(403).json({ valid: false, error: 'Key not found in cache.' });
    }
  } catch (error) {
    logWithRequestIp('error', req, 'Auth key validation failed:', error.message);
    logWithRequestIp('error', req, `Failed device token: ${authKey.substring(0, 8)}...`);
    return res.status(401).json({ valid: false, error: 'Invalid or expired authKey.' });
  }
}));

const monitoringCorsFn = cors({
  origin: process.env.MONITORING_ORIGIN || 'false',
  methods: ['GET'],
  allowedHeaders: ['Content-Type']
});

app.get('/metrics', monitoringCorsFn, async (req, res) => {
  try {
    logWithRequestIp('debug', req, 'Metrics endpoint accessed');
    const uptime = (Date.now() - startTime) / 1000;
    uptimeGauge.set(uptime);

    res.set('Content-Type', register.contentType);
    res.end(await register.metrics());
  } catch (err) {
    res.status(500).end(err);
  }
});

app.use((req, res, next) => {
  logWithRequestIp('debug', req, `404 Not Found: ${req.method} ${req.originalUrl}`);
  // If it's a GET, return a JSON error
  if (req.method === 'GET') {
    return res.status(404).json({ error: 'Not found' });
  }
  // For other methods, plain text
  res.status(404).send('Not found');
});

app.listen(port, () => {
  console.log(`Nickel-Auth (v${version}) running on port: ${port}`);
});
