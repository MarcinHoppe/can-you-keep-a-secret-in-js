const crypto = require('crypto').webcrypto;

(async () => {
  // ----------------- HIGH LEVEL FLOW -----------------

  async function seal({ encryptionKey, signingKey }, userData) {
    const iv = generateIv();
    const ciphertext = await encrypt(encryptionKey, iv, userData);
    const signature = await signGenerate(signingKey, iv, ciphertext);
    return serialize(iv, ciphertext, signature);
  }

  async function unseal({ encryptionKey, signingKey }, secretToken) {
    const [iv, ciphertext, signature] = deserialize(secretToken);
    if (!await signVerify(signingKey, iv, ciphertext, signature)) {
      throw new Error('Invalid signature');
    }
    return decrypt(encryptionKey, iv, ciphertext);
  }

  // ----------------- PRIMITIVES -----------------

  async function generateKeys() {
    return {
      encryptionKey: await crypto.subtle.generateKey(
        { name: 'AES-CBC', length: 128 },
        true,
        ['encrypt', 'decrypt']
      ),
      signingKey: await crypto.subtle.generateKey(
        { name: 'HMAC', hash: { name: 'SHA-256' } },
        true,
        ['sign', 'verify']
      )
    };
  }

  function generateIv() {
    const iv = new Uint8Array(16);
    return crypto.getRandomValues(iv);
  }

  async function encrypt(key, iv, userData) {
    const userDataBytes = new TextEncoder().encode(userData);
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-CBC', iv },
      key,
      userDataBytes
    );
    return new Uint8Array(ciphertext);
  }

  async function decrypt(key, iv, ciphertext) {
    const plaintext = await crypto.subtle.decrypt(
      { name: 'AES-CBC', iv },
      key,
      ciphertext
    );
    return new TextDecoder().decode(plaintext);
  }

  async function signGenerate(key, iv, ciphertext) {
    const payload = new Uint8Array([...iv, ...ciphertext]);
    const signature = await crypto.subtle.sign(
      'HMAC',
      key,
      payload
    );
    return new Uint8Array(signature);
  }

  async function signVerify(key, iv, ciphertext, signature) {
    const payload = new Uint8Array([...iv, ...ciphertext]);
    return crypto.subtle.verify(
      'HMAC',
      key,
      signature,
      payload
    );
  }

  function serialize(iv, ciphertext, signature) {
    return new Uint8Array([...iv, ...ciphertext, ...signature]);
  }

  function deserialize(secretToken) {
    const ciphertextLen = secretToken.length - 48;
    return [
      secretToken.subarray(0,16),
      secretToken.subarray(16, 16 + ciphertextLen),
      secretToken.subarray(16 + ciphertextLen)
    ];
  }

  // ----------------- USAGE -----------------

  const keys = await generateKeys();
  const secret = 'Hello from JS Poland!';

  const secretToken = await seal(keys, secret);
  const recoveredSecret = await unseal(keys, secretToken);

  console.assert(
    secret === recoveredSecret,
    'Original secret and recovered secret must be the same.'
  );
})();
