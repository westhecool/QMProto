const crypto = require('node:crypto');
const fs = require('node:fs');

class Crypto {
    constructor(keyDirectory = 'keys') {
        this.keyDirectory = keyDirectory;
        if (!fs.existsSync(keyDirectory)) fs.mkdirSync(keyDirectory, { recursive: true });
        if (fs.existsSync(`${keyDirectory}/public.pem`) && fs.existsSync(`${keyDirectory}/private.pem`)) {
            QMPROTO_DEBUG_FN('Using existing public and private keys...');
            this.publicKey = crypto.createPublicKey({
                key: fs.readFileSync(`${keyDirectory}/public.pem`),
                type: 'spki',
                format: 'pem',
            });
            this.privateKey = crypto.createPrivateKey({
                key: fs.readFileSync(`${keyDirectory}/private.pem`),
                type: 'pkcs8',
                format: 'pem',
            });
        } else {
            QMPROTO_DEBUG_FN('Generating new public and private keys...');
            const { publicKey, privateKey } = crypto.generateKeyPairSync('ml-kem-1024');
            const publicKeyPem = publicKey.export({
                type: 'spki',
                format: 'pem',
            });
            fs.writeFileSync(`${keyDirectory}/public.pem`, publicKeyPem);
            const privateKeyPem = privateKey.export({
                type: 'pkcs8',
                format: 'pem',
            });
            fs.writeFileSync(`${keyDirectory}/private.pem`, privateKeyPem);
            this.publicKey = publicKey;
            this.privateKey = privateKey;
        }
        this.publicKeyRaw = this.publicKey.export({ format: 'raw-public' });
        this.publicKeyId = this.hash(this.publicKeyRaw, 'sha3-256');
        this.publicKeyIdString = this.publicKeyId.toString('hex');
        QMPROTO_DEBUG_FN(`Public key identifier: ${this.publicKeyIdString}`);
    }

    hash(data, algorithm = 'sha256') {
        return crypto.createHash(algorithm).update(data).digest();
    }

    encrypt(publicKey, data) {
        const result = [];
        if (publicKey instanceof Buffer || publicKey instanceof Uint8Array) publicKey = crypto.createPublicKey({ key: publicKey, format: 'raw-public', asymmetricKeyType: 'ml-kem-1024' });
        const { sharedKey, ciphertext: keyCipherText } = crypto.encapsulate(publicKey);
        result.push(keyCipherText);
        const iv = crypto.randomBytes(12);
        result.push(iv);
        const cipher = crypto.createCipheriv('aes-256-gcm', sharedKey, iv);
        for (let i = 0; i < data.length; i += 1_000_000) {
            result.push(cipher.update(data.subarray(i, i + 1_000_000)));
        }
        result.push(cipher.final());
        result.push(cipher.getAuthTag());
        return Buffer.concat(result);
    }

    decrypt(data) {
        const result = [];
        // 1568b shared key + 12b iv + cipherText + 16b auth tag
        if (data.length < 1596) throw new Error('Invalid data');
        let offset = 0;
        const keyCipherText = data.subarray(offset, offset + 1568);
        offset += 1568;
        const iv = data.subarray(offset, offset + 12);
        offset += 12;
        const authTag = data.subarray(data.length - 16);
        const cipherText = data.subarray(offset, data.length - 16);
        const sharedKey = crypto.decapsulate(this.privateKey, keyCipherText);
        const decipher = crypto.createDecipheriv('aes-256-gcm', sharedKey, iv);
        decipher.setAuthTag(authTag);
        for (let i = 0; i < cipherText.length; i += 1_000_000) {
            result.push(decipher.update(cipherText.subarray(i, i + 1_000_000)));
        }
        result.push(decipher.final());
        return Buffer.concat(result);
    }
}

module.exports = Crypto;