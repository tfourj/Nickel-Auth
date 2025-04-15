import rateLimit from 'express-rate-limit';
import fs from 'fs';
import { authCache } from './server.js';

const maxLimitReq = parseInt(process.env.RATE_LIMIT) || 50;
const bannedIpsFile = './banned.ips';

export function addIpToBannedList(ip) {
  try {
    fs.appendFileSync(bannedIpsFile, `${ip}\n`, 'utf8');
    console.log(`IP ${ip} added to banned list.`);
  } catch (err) {
    console.error(`Failed to write IP ${ip} to banned list:`, err.message);
  }
}

function getClientIp(req) {
  const forwardedFor = req.headers['cf-connecting-ip'];
  return forwardedFor ? forwardedFor.split(',')[0].trim() : req.ip;
}

// Main rate limiter for all requests
export const limiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: maxLimitReq,
  message: 'Too many requests from this IP, please try again later.',
  headers: true,
  keyGenerator: getClientIp,
  handler: (req, res, next) => {
    const ip = req.headers['cf-connecting-ip'] || req.ip;
    console.error(`Blacklisted IP due to rate limit: ${ip}`);
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
  keyGenerator: getClientIp
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
    
    // Clear the existing keys
    Object.keys(apiKeysObj).forEach(key => delete apiKeysObj[key]);
    
    // Normalize keys by removing trailing slashes
    Object.keys(rawKeys).forEach(key => {
      const normalizedKey = key.replace(/\/+$/, '');
      apiKeysObj[normalizedKey] = rawKeys[key];
    });
    
    console.log('🔁 Reloaded API keys');
  } catch (err) {
    console.error('❌ Failed to load api_keys.json:', err.message);
  }
}

export async function validateDeviceToken(deviceToken) {
  if (!deviceToken || typeof deviceToken !== 'string') {
    console.error('Invalid device token.');
    return false;
  }

  console.log('Validating device token.');

  if (authCache.has(deviceToken)) return true;

  console.error('Device token validation failed.');
  return false;
}