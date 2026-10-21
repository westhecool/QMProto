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
        this.publicKeyId = this.hash(this.publicKeyRaw);
        this.publicKeyIdString = this.publicKeyId.toString('hex');
        QMPROTO_DEBUG_FN(`Public key identifier: ${this.publicKeyIdString}`);
    }

    timingSafeEqual(a, b) {
        return crypto.timingSafeEqual(a, b);
    }

    randomBytes(len) {
        return crypto.randomBytes(len);
    }

    hash(data, algorithm = 'sha3-256') {
        return crypto.createHash(algorithm).update(data).digest();
    }

    hmac(key, data, algorithm = 'sha3-256') {
        return crypto.createHmac(algorithm, key).update(data).digest();
    }

    createChallenge(publicKey, len = 32) {
        const { sharedKey, ciphertext: keyCipherText } = this.encapsulate(publicKey);
        const seed = this.randomBytes(len);
        const expectedResponse = this.hmac(sharedKey, seed);
        return { expectedResponse, challengeBuffer: Buffer.concat([keyCipherText, seed]) };
    }

    solveChallenge(data) {
        // 1568b key cipher + seed
        if (data.length <= 1568) throw new Error('Invalid challenge length.');
        const keyCipherText = data.subarray(0, 1568);
        const seed = data.subarray(1568);
        const sharedKey = this.decapsulate(keyCipherText);
        const response = this.hmac(sharedKey, seed);
        return response;
    }

    encapsulate(publicKey) {
        if (publicKey instanceof Buffer || publicKey instanceof Uint8Array) publicKey = crypto.createPublicKey({ key: publicKey, format: 'raw-public', asymmetricKeyType: 'ml-kem-1024' });
        return crypto.encapsulate(publicKey);
    }

    decapsulate(keyCipherText) {
        return crypto.decapsulate(this.privateKey, keyCipherText);
    }

    PKIEncrypt(publicKey, data) {
        const { sharedKey, ciphertext: keyCipherText } = this.encapsulate(publicKey);
        const cipherText = this.AESEncrypt(sharedKey, data);
        return Buffer.concat([keyCipherText, cipherText]);
    }

    PKIDecrypt(data) {
        // 1568b shared key + 12b iv + cipherText + 16b auth tag
        if (data.length <= 1596) throw new Error('Invalid data length.');
        const keyCipherText = data.subarray(0, 1568);
        const sharedKey = this.decapsulate(keyCipherText);
        return this.AESDecrypt(sharedKey, data.subarray(1568));
    }

    AESEncrypt(key, data) {
        if (typeof key === 'string') key = Buffer.from(key, 'hex');
        const result = [];
        const iv = crypto.randomBytes(12);
        result.push(iv);
        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
        for (let i = 0; i < data.length; i += 1_000_000) {
            result.push(cipher.update(data.subarray(i, i + 1_000_000)));
        }
        result.push(cipher.final());
        result.push(cipher.getAuthTag());
        return Buffer.concat(result);
    }

    AESDecrypt(key, data) {
        if (typeof key === 'string') key = Buffer.from(key, 'hex');
        const result = [];
        // 12b iv + cipherText + 16b auth tag
        if (data.length <= 28) throw new Error('Invalid data length.');
        let offset = 0;
        const iv = data.subarray(offset, offset + 12);
        offset += 12;
        const cipherText = data.subarray(offset, data.length - 16);
        const authTag = data.subarray(data.length - 16);
        const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
        decipher.setAuthTag(authTag);
        for (let i = 0; i < cipherText.length; i += 1_000_000) {
            result.push(decipher.update(cipherText.subarray(i, i + 1_000_000)));
        }
        result.push(decipher.final());
        return Buffer.concat(result);
    }
}

module.exports = Crypto;