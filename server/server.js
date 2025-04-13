// server.js
import express from 'express';
import rateLimit from 'express-rate-limit';
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

dotenv.config();

let requestCount = 0; // Track total requests
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

const authCache = new NodeCache({ stdTTL: 600 }); // 10 minutes
app.use(bodyParser.json());

app.use(helmet());

app.use((req, res, next) => {
  if (req.body) {
    req.body = JSON.parse(xss(JSON.stringify(req.body)));
  }
  next();
});

function validateInput(input, type = 'string') {
  if (type === 'string' && (typeof input !== 'string' || input.trim() === '')) {
    throw new Error('Invalid input: Expected a non-empty string.');
  }
  if (type === 'object' && (typeof input !== 'object' || input === null)) {
    throw new Error('Invalid input: Expected a valid object.');
  }
  return input;
}

const bannedIpsFile = './banned.ips';
function addIpToBannedList(ip) {
  try {
    fs.appendFileSync(bannedIpsFile, `${ip}\n`, 'utf8');
    console.log(`IP ${ip} added to banned list.`);
  } catch (err) {
    console.error(`Failed to write IP ${ip} to banned list:`, err.message);
  }
}

// Rate limiter
const limiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: maxLimitReq,
  message: 'Too many requests from this IP, please try again later.',
  headers: true,
  keyGenerator: (req) => {
    const forwardedFor = req.headers['cf-connecting-ip'];
    const clientIp = forwardedFor ? forwardedFor.split(',')[0].trim() : req.ip;
    return clientIp;
  },
  handler: (req, res, next) => {
    const ip = req.headers['cf-connecting-ip'] || req.ip;
    console.error(`Blacklisted IP due to rate limit: ${ip}`);
    addIpToBannedList(ip);
    res.status(429).send('Too many requests from this IP, please try again later.');
  },
});
app.use(limiter);

// Load API keys map
let apiKeys = {};
function loadApiKeys() {
  try {
    const raw = fs.readFileSync('./api_keys.json');
    apiKeys = JSON.parse(raw);
    console.log('🔁 Reloaded API keys');
  } catch (err) {
    console.error('❌ Failed to load api_keys.json:', err.message);
  }
}
loadApiKeys();

// Watch for changes in api_keys.json
chokidar.watch('./api_keys.json').on('change', loadApiKeys);

async function validateDeviceToken(deviceToken) {
  if (!deviceToken || typeof deviceToken !== 'string') {
    console.error('Invalid device token.');
    return false;
  }

  console.log('Validating device token.');

  if (authCache.has(deviceToken)) return true;

  console.error('Device token validation failed.');
  return false;
}

app.get('/ios-challenge', (req, res) => {
    requestCount++;
    const challenge = uuidv4();
    console.log(`Challenge was requested, returning ${challenge}`);
    res.send(JSON.stringify({ challenge }));
});

app.post('/ios-auth', async (req, res) => {
  requestCount++;
  console.log('Auth request received');
  try {
    const { attestation, challenge, keyId } = req.body;

    // Validate inputs
    validateInput(attestation);
    validateInput(challenge);
    validateInput(keyId);

    console.log('Validating attestation...');
    const result = verifyAttestation({
      attestation: Buffer.from(attestation, 'base64'),
      challenge,
      keyId,
      bundleIdentifier: bundleId,
      teamIdentifier: teamId,
      allowDevelopmentEnvironment: process.env.NODE_ENV !== 'production',
    });

    console.log('Attestation validated successfully');

    // Generate a temporary 10-minute key
    const tempKey = jwt.sign(
      { keyId, exp: Math.floor(Date.now() / 1000) + 600 }, // 10 minutes
      jwtSecret
    );
    authCache.set(tempKey, result.publicKey);

    res.status(200).json({ tempKey });
  } catch (error) {
    console.error('Error in /ios-auth:', error.message);
    res.status(400).json({ error: error.message });
  }
});

app.post('/ios-request', async (req, res) => {
  requestCount++;
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

    // Validate API URL
    validateInput(apiUrl);

    const customAuth = apiKeys[apiUrl];
    if (!customAuth) {
      throw new Error('API not added to authentication server.');
    }

    console.log('Making request to Cobalt API:', apiUrl);

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
});

app.post('/ios-validate', async (req, res) => {
  requestCount++;
  console.log(`Validation request received`);
  const authHeader = req.headers['authorization'] || '';
  const [authType, authKey] = authHeader.split(' ');

  if (authType !== 'Nickel-Auth' || !authKey) {
    return res.status(400).json({ error: 'Invalid or missing authorization header.' });
  }

  try {
    if (authCache.has(authKey)) { // Validate using tempKey
      return res.status(200).json({ valid: true });
    } else {
      return res.status(403).json({ valid: false, error: 'Key not found in cache.' });
    }
  } catch (error) {
    console.error('Auth key validation failed:', error.message);c
    return res.status(401).json({ valid: false, error: 'Invalid or expired authKey.' });
  }
});

// Monitoring API
app.get('/monitor', (req, res) => {
  res.status(200).json({
    totalRequests: requestCount,
    cacheStats: authCache.getStats(),
  });
});

app.listen(port, () => {
  console.log(`Nickel proxy running on port ${port}`);
});
