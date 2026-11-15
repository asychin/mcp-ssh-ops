// Exercise ssh2's OpenSSL/WASM fallback even when its optional addon is installed.
const crypto = require('ssh2/lib/protocol/crypto.js');
const { createCipher, createDecipher } = crypto;
crypto.bindingAvailable = false;
crypto.createCipher = (config) => createCipher({
  ...config, outbound: { ...config.outbound, forceNative: true },
});
crypto.createDecipher = (config) => createDecipher({
  ...config, inbound: { ...config.inbound, forceNative: true },
});
