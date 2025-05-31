// server.js
import express from 'express';
import axios from 'axios';
import bodyParser from 'body-parser';
import NodeCache from 'node-cache';
import fs from 'fs';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import chokidar from 'chokidar';
import { v4 as uuidv4 } from 'uuid';
import { verifyAttestation } from 'node-app-attest';
import xss from 'xss';
import helmet from 'helmet';
import client from 'prom-client';
import cors from 'cors';
import { limiter, challengeLimiter, validateInput, loadApiKeys, validateDeviceToken, extractDomain } from './utils.js';

dotenv.config();

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

const challengeTTL = parseInt(process.env.CHALLENGE_CACHE_TTL) || 300;
const authTTL = parseInt(process.env.AUTH_CACHE_TTL) || 600;

export const authCache = new NodeCache({ stdTTL: authTTL }); // 10 minutes
export const challengeCache = new NodeCache({ stdTTL: challengeTTL }); // 5 minutes
export let apiKeys = {};

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

// --- ENDPOINTS ---

app.get('/ios-challenge', challengeLimiter, trackAuthResponseTime((req, res) => {
    const challenge = uuidv4();
    challengeCache.set(challenge, true);
    console.log(`Challenge was requested, returning ${challenge}`);
    res.send(JSON.stringify({ challenge }));
}));

app.post('/ios-auth', trackAuthResponseTime(async (req, res) => {
  console.log('Auth request received');
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

    console.log(`Validating attestation - Challenge: ${challenge.substring(0, 8)}..., KeyId: ${keyId.substring(0, 8)}..., Attestation: ${attestation.substring(0, 16)}...`);
    
    const result = await Promise.resolve(verifyAttestation({
      attestation: Buffer.from(attestation, 'base64'),
      challenge,
      keyId,
      bundleIdentifier: bundleId,
      teamIdentifier: teamId,
      allowDevelopmentEnvironment: process.env.NODE_ENV !== 'production',
    }));

    console.log('Attestation validated successfully');

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
    console.error('Error in /ios-auth:', error.message);
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
    
    const customAuth = apiKeys[normalizedUrl];
    if (!customAuth) {
      throw new Error('API not added to authentication server.');
    }

    console.log(`Making request to Cobalt API for: ${domain} to instance url: ${apiUrl}`);

    const cobaltRes = await axios.post(apiUrl, filteredBody, {
      headers: {
        Authorization: `Api-Key ${customAuth}`,
        Accept: 'application/json',
      },
    });
    res.status(cobaltRes.status).json(cobaltRes.data);
  } catch (err) {
    if (err.response) {
      console.error('Error in /ios-request:', err.response.data);
      res.status(err.response.status).json(err.response.data);
    } else {
      console.error('Error in /ios-request:', err.message);
      res.status(500).json({ error: 'Internal server error' });
    }
  }
}));

app.post('/ios-validate', trackAuthResponseTime(async (req, res) => {
  const authHeader = req.headers['authorization'] || '';
  const [authType, authKey] = authHeader.split(' ');
  console.log(`Validating device token: ${authKey.substring(0, 8)}...`);

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
      console.log(`Device token validation failed - not found in cache: ${authKey.substring(0, 8)}...`);
      return res.status(403).json({ valid: false, error: 'Key not found in cache.' });
    }
  } catch (error) {
    console.error('Auth key validation failed:', error.message);
    console.error(`Failed device token: ${authKey.substring(0, 8)}...`);
    return res.status(401).json({ valid: false, error: 'Invalid or expired authKey.' });
  }
}));

const monitoringCorsFn = cors({
  origin: process.env.MONITORING_ORIGIN || '*',
  methods: ['GET'],
  allowedHeaders: ['Content-Type']
});

app.get('/metrics', monitoringCorsFn, async (req, res) => {
  try {
    const uptime = (Date.now() - startTime) / 1000;
    uptimeGauge.set(uptime);

    res.set('Content-Type', register.contentType);
    res.end(await register.metrics());
  } catch (err) {
    res.status(500).end(err);
  }
});

app.use((req, res, next) => {
  //console.log(`404 Not Found: ${req.method} ${req.originalUrl}`);
  // If it's a GET, return a JSON error
  if (req.method === 'GET') {
    return res.status(404).json({ error: 'Not found' });
  }
  // For other methods, plain text
  res.status(404).send('Not found');
});

app.listen(port, () => {
  console.log(`Nickel proxy running on port ${port}`);
});
