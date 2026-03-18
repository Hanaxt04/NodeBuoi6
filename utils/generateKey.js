const { generateKeyPairSync } = require('crypto');
const fs = require('fs');

const { publicKey, privateKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048, // đúng yêu cầu đề
  publicKeyEncoding: {
    type: 'spki',
    format: 'pem'
  },
  privateKeyEncoding: {
    type: 'pkcs8',
    format: 'pem'
  }
});

// lưu file
fs.writeFileSync('private.key', privateKey);
fs.writeFileSync('public.key', publicKey);

console.log("Đã tạo key thành công!");