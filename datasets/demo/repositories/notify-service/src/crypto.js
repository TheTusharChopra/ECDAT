'use strict';
const crypto = require('crypto');

// AES-256-GCM for payload confidentiality.
function sealPayload(key, plaintext) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { iv, enc, tag: cipher.getAuthTag() };
}

// Webhook authentication tag.
function webhookSignature(secret, body) {
  return crypto.createHmac('sha256', secret).update(body).digest('hex');
}

// Deduplication only -- NOT a security control.
function dedupeKey(message) {
  return crypto.createHash('md5').update(message).digest('hex');
}

// RSA-2048 signing for partner callbacks.
function signCallback(privateKey, payload) {
  const signer = crypto.createSign('RSA-SHA256');
  signer.update(payload);
  return signer.sign(privateKey, 'base64');
}

module.exports = { sealPayload, webhookSignature, dedupeKey, signCallback };
