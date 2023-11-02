const assert = require('assert');
const crypto = require('crypto');

// ----------------- HIGH LEVEL FLOW -----------------

function seal({ encryptionKey, signingKey }, userData) {
  const iv = generateIv();
  const ciphertext = encrypt(encryptionKey, iv, userData);
  const signature = signGenerate(signingKey, iv, ciphertext);
  return serialize(iv, ciphertext, signature);
}

function unseal({ encryptionKey, signingKey }, secretToken) {
  const [iv, ciphertext, signature] = deserialize(secretToken);
  signVerify(signingKey, iv, ciphertext, signature);
  return decrypt(encryptionKey, iv, ciphertext);
}

// ----------------- PRIMITIVES -----------------

function generateKeys() {
  return {
    encryptionKey: crypto.generateKeySync('aes', { length: 128 }),
    signingKey: crypto.generateKeySync('hmac', { length: 128 })
  }
}

function generateIv() {
  return crypto.randomBytes(16);
}

function encrypt(key, iv, userData) {
  const userDataBytes = Buffer.from(userData, 'utf-8');
  const encryptor = crypto.createCipheriv('aes-128-cbc', key, iv);
  return Buffer.concat([
    encryptor.update(userDataBytes),
    encryptor.final()
  ]);
}

function decrypt(key, iv, ciphertext) {
  const decryptor = crypto.createDecipheriv('aes-128-cbc', key, iv);
  return Buffer.concat([
    decryptor.update(ciphertext),
    decryptor.final()
  ]).toString('utf-8');
}

function signGenerate(key, iv, ciphertext) {
  const signer = crypto.createHmac('sha256', key);
  signer.update(iv);
  signer.update(ciphertext);
  return signer.digest();
}

function signVerify(key, iv, ciphertext, signature) {
  return crypto.timingSafeEqual(
    signature,
    signGenerate(key, iv, ciphertext)
  );
}

function serialize(iv, ciphertext, signature) {
  return Buffer.concat([iv, ciphertext, signature]);
}

function deserialize(secretToken) {
  const ciphertextLen = secretToken.length - 48;
  return [
    secretToken.subarray(0, 16),
    secretToken.subarray(16, 16 + ciphertextLen),
    secretToken.subarray(16 + ciphertextLen)
  ]
}

// ----------------- USAGE -----------------

const keys = generateKeys();
const secret = 'Hello from JS Poland!';

const secretToken = seal(keys, secret);
const recoveredSecret = unseal(keys, secretToken);

assert.deepStrictEqual(
  recoveredSecret,
  secret,
  'Original secret and recovered secret must be the same.'
);
