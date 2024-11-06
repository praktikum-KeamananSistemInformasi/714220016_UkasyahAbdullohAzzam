const express = require('express');
const crypto = require('crypto');
const bodyParser = require('body-parser');
const app = express();

app.use(bodyParser.urlencoded({ extended: true }));
app.set('view engine', 'ejs');

// Generate random keys for each algorithm
const keyAES = crypto.randomBytes(32);  // 256-bit key for AES
const keyDES = crypto.randomBytes(8);   // 64-bit key for DES
const keyChaCha20 = crypto.randomBytes(32);  // 256-bit key for ChaCha20

// AES encryption/decryption
function encryptAES(plainText) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-gcm', keyAES, iv);
    const encrypted = Buffer.concat([cipher.update(plainText, 'utf8'), cipher.final()]);
    return Buffer.concat([iv, encrypted]).toString('base64');
}

function decryptAES(cipherText) {
    const data = Buffer.from(cipherText, 'base64');
    const iv = data.slice(0, 16);
    const encryptedText = data.slice(16);
    const decipher = crypto.createDecipheriv('aes-256-gcm', keyAES, iv);
    return decipher.update(encryptedText, 'base64', 'utf8') + decipher.final('utf8');
}

// DES encryption/decryption
function encryptDES(plainText) {
    const iv = crypto.randomBytes(8);
    const cipher = crypto.createCipheriv('des-ede3-cbc', keyDES, iv);
    const encrypted = Buffer.concat([cipher.update(plainText, 'utf8'), cipher.final()]);
    return Buffer.concat([iv, encrypted]).toString('base64');
}

function decryptDES(cipherText) {
    const data = Buffer.from(cipherText, 'base64');
    const iv = data.slice(0, 8);
    const encryptedText = data.slice(8);
    const decipher = crypto.createDecipheriv('des-ede3-cbc', keyDES, iv);
    return decipher.update(encryptedText, 'base64', 'utf8') + decipher.final('utf8');
}

// ChaCha20 encryption/decryption
function encryptChaCha20(plainText) {
    const nonce = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('chacha20-poly1305', keyChaCha20, nonce, { authTagLength: 16 });
    const encrypted = Buffer.concat([cipher.update(plainText, 'utf8'), cipher.final()]);
    return Buffer.concat([nonce, encrypted, cipher.getAuthTag()]).toString('base64');
}

function decryptChaCha20(cipherText) {
    const data = Buffer.from(cipherText, 'base64');
    const nonce = data.slice(0, 12);
    const encryptedText = data.slice(12, -16);
    const authTag = data.slice(-16);
    const decipher = crypto.createDecipheriv('chacha20-poly1305', keyChaCha20, nonce, { authTagLength: 16 });
    decipher.setAuthTag(authTag);
    return decipher.update(encryptedText, 'base64', 'utf8') + decipher.final('utf8');
}

app.get('/', (req, res) => {
    res.render('index', { result: "" });
});

app.post('/encrypt', (req, res) => {
    const { plain_text, algorithm } = req.body;
    let encryptedText;

    switch (algorithm) {
        case "AES":
            encryptedText = encryptAES(plain_text);
            break;
        case "DES":
            encryptedText = encryptDES(plain_text);
            break;
        case "ChaCha20":
            encryptedText = encryptChaCha20(plain_text);
            break;
        default:
            encryptedText = "Unsupported algorithm";
    }

    res.render('index', { result: `Encrypted: ${encryptedText}`, algorithm });
});

app.post('/decrypt', (req, res) => {
    const { cipher_text, algorithm } = req.body;
    let decryptedText;

    try {
        switch (algorithm) {
            case "AES":
                decryptedText = decryptAES(cipher_text);
                break;
            case "DES":
                decryptedText = decryptDES(cipher_text);
                break;
            case "ChaCha20":
                decryptedText = decryptChaCha20(cipher_text);
                break;
            default:
                decryptedText = "Unsupported algorithm";
        }
    } catch (error) {
        decryptedText = `Error: ${error.message}`;
    }

    res.render('index', { result: `Decrypted: ${decryptedText}`, algorithm });
});

app.listen(3000, () => {
    console.log('Server is running on http://localhost:3000');
});
