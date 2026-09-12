const process = require('node:process');
if (!process.versions.openssl.startsWith('3.5.')) throw new Error(`[QMPROTO]: Missing OpenSSL version >= 3.5.0 (current: ${process.versions.openssl})`);
global.QMPROTO_DEBUG_FN = (...args) => { if (process.env.QMPROTO_DEBUG == 'true' || process.env.QMPROTO_DEBUG == '1') console.log('[QMPROTO-DEBUG]:', ...args); };
const Crypto = require('./crypto.js');
const { EventEmitter } = require('node:events');
const { MESSAGES } = require('./constants.js');

class QMProto extends EventEmitter {
    constructor({ keyDirectory, maxMessageSize, maxMessageForwardSize, sendHelloOnConnect, respondToDiscover, locateTimeout } = {}) {
        super();
        if (typeof maxMessageSize !== 'number') maxMessageSize = 20 * 1024 * 1024;
        if (typeof maxMessageForwardSize !== 'number') maxMessageForwardSize = 20 * 1024 * 1024;
        if (typeof sendHelloOnConnect !== 'boolean') sendHelloOnConnect = false;
        if (typeof respondToDiscover !== 'boolean') respondToDiscover = true;
        if (typeof locateTimeout !== 'number') locateTimeout = 6000;
        this.maxMessageSize = maxMessageSize;
        this.maxMessageForwardSize = maxMessageForwardSize;
        this.sendHelloOnConnect = sendHelloOnConnect;
        this.respondToDiscover = respondToDiscover;
        this.locateTimeout = locateTimeout;
        this.crypto = new Crypto(keyDirectory);
        this.identity = this.crypto.publicKeyId;
        this.identityString = this.crypto.publicKeyIdString;
        this.streams = {};
        this.knownPeers = {};
        this.broadcastIdentity = Buffer.alloc(32).fill(0xFF);
        this._knownPeersCleanupInterval = setInterval(() => this._cleanupKnownPeers(), 3000);
        this.recevedMessages = {};
        this._recevedMessagesCleanupInterval = setInterval(() => this._cleanupReceivedMessages(), 3000);
        this._pingCBs = {};
        this._queryCBs = {};
    }
    _genId() {
        const buf = Buffer.alloc(8);
        buf.writeBigUInt64BE(BigInt(Date.now()));
        buf.writeUInt16BE(Math.floor(Math.random() * 0xFFFF)); // Overwrite the first 2 bytes (00 00) with a random number
        return buf;
    }
    _onNewStream(stream, streamSourceInfo) {
        const streamId = this._genId().toString('hex');
        try {
            stream.onMessage = (data) => this._onMessage(streamId, data);
            stream.onClose = () => { };
            this.streams[streamId] = stream;
            this.streams[streamId].onMessage = (data) => this._onRawMessage(streamId, data);
            this.streams[streamId].onClose = () => this._onStreamClose(streamId);
            if (this.sendHelloOnConnect) this.streams[streamId].sendMessage(this._encodeMessage(this.broadcastIdentity, MESSAGES.HELLO).buffer);
        } catch (e) {
            QMPROTO_DEBUG_FN(`Error registering stream ${streamId}:`, e.message);
        }
    }
    _onStreamClose(streamId) {
        for (const peer in this.knownPeers) if (this.knownPeers[peer][0] === streamId) this._markPeerAsDead(peer);
        delete this.streams[streamId];
    }
    _onRawMessage(streamId, data) {
        try {
            const msg = this._decodeMessage(data);
            if (msg.senderIdentityString === this.identityString) return; // Ignore our own messages that may have been forwarded to us
            if (this.knownPeers[msg.senderIdentityString]) {
                if (this.knownPeers[msg.senderIdentityString][0] !== streamId) this.knownPeers[msg.senderIdentityString][0] = streamId;
                this.knownPeers[msg.senderIdentityString][2] = Math.floor(Date.now() / 1000) + 60;
            }
            else this.knownPeers[msg.senderIdentityString] = [streamId, msg.senderPubKey, Math.floor(Date.now() / 1000) + 60];
            if (this.recevedMessages[msg.idString]) return; // Ignore duplicate messages
            this.recevedMessages[msg.idString] = Math.floor(Date.now() / 1000) + 5;
            // Messages that could be broadcast
            if ((msg.message === MESSAGES.HELLO || msg.message === MESSAGES.DISCOVER) && (msg.recipientString === this.identityString || this._checkIfBroadcast(msg.recipient))) {
                switch (msg.message) {
                    case MESSAGES.HELLO:
                        this.emit('new-peer', msg, msg.senderIdentityString);
                        break;
                    case MESSAGES.DISCOVER:
                        this.emit('discover-request', msg);
                        if (this.respondToDiscover) this.streams[streamId].sendMessage(this._encodeMessage(msg.senderIdentity, MESSAGES.HELLO).buffer);
                        break;
                }
            }
            if (msg.recipientString === this.identityString) {
                if ((msg.encryptedPayload.length - 1596) > this.maxMessageSize) { // 1596b encryption overhead
                    QMPROTO_DEBUG_FN(`Dropping message with payload too large (${msg.encryptedPayload.length} bytes > max ${this.maxMessageSize} bytes)`);
                    return;
                }
                let payload = new Uint8Array(0);
                switch (msg.message) {
                    case MESSAGES.PING:
                        if (msg.encryptedPayload.length > 0) payload = this.crypto.decrypt(msg.encryptedPayload);
                        this.emit('ping', msg);
                        this.streams[streamId].sendMessage(this._encodeMessage(msg.senderIdentity, MESSAGES.PONG, this.crypto.encrypt(msg.senderPubKey, msg.id)).buffer);
                        break;
                    case MESSAGES.PONG:
                        if (msg.encryptedPayload.length > 0) payload = this.crypto.decrypt(msg.encryptedPayload);
                        this.emit('pong', msg);
                        if (payload.length === 8 && this._pingCBs[payload.toString('hex')]) this._pingCBs[payload.toString('hex')](0);
                        break;
                    case MESSAGES.ANOUNCE:
                        if (msg.encryptedPayload.length > 0) payload = this.crypto.decrypt(msg.encryptedPayload);
                        this.emit('announcement', msg, payload);
                        break;
                    case MESSAGES.QUERY:
                        if (msg.encryptedPayload.length > 0) payload = this.crypto.decrypt(msg.encryptedPayload);
                        this.emit('query', msg, payload, async (data = new Uint8Array(0)) => await this._sendQueryResponse(msg, MESSAGES.QUERY_SUCCESS, data), async (data = new Uint8Array(0)) => await this._sendQueryResponse(msg, MESSAGES.QUERY_FAILURE, data), async (data = new Uint8Array(0)) => await this._sendQueryResponse(msg, MESSAGES.QUERY_REFUSED, data));
                        break;
                    case MESSAGES.QUERY_SUCCESS:
                        if (msg.encryptedPayload.length > 0) payload = this.crypto.decrypt(msg.encryptedPayload);
                        if (payload.length >= 8) {
                            const k = payload.subarray(0, 8).toString('hex');
                            if (this._queryCBs[k]) this._queryCBs[k]([0, 0, payload.subarray(8)]);
                        }
                        break;
                    case MESSAGES.QUERY_FAILURE:
                        if (msg.encryptedPayload.length > 0) payload = this.crypto.decrypt(msg.encryptedPayload);
                        if (payload.length >= 8) {
                            const k = payload.subarray(0, 8).toString('hex');
                            if (this._queryCBs[k]) this._queryCBs[k]([0, 1, payload.subarray(8)]);
                        }
                        break;
                    case MESSAGES.QUERY_REFUSED:
                        if (msg.encryptedPayload.length > 0) payload = this.crypto.decrypt(msg.encryptedPayload);
                        if (payload.length >= 8) {
                            const k = payload.subarray(0, 8).toString('hex');
                            if (this._queryCBs[k]) this._queryCBs[k]([0, 2, payload.subarray(8)]);
                        }
                        break;
                }
            } else {
                if ((msg.encryptedPayload.length - 1596) > this.maxMessageForwardSize) { // 1596b encryption overhead
                    QMPROTO_DEBUG_FN(`Dropping message forward with payload too large (${msg.encryptedPayload.length} bytes > max ${this.maxMessageForwardSize} bytes)`);
                    return;
                }
                if (this.knownPeers[msg.recipientString] && !this._checkIfBroadcast(msg.recipient)) {
                    this.streams[this.knownPeers[msg.recipientString][0]].sendMessage(data);
                } else {
                    for (const stream in this.streams) {
                        if (stream === streamId) continue; // Don't forward the message back to the sender
                        this.streams[stream].sendMessage(data);
                    }
                }
            }
        } catch (e) {
            QMPROTO_DEBUG_FN('Error decoding incoming message:', e.message);
            throw e;
        }
    }
    _cleanupReceivedMessages() {
        for (const id in this.recevedMessages) {
            if (Math.floor(Date.now() / 1000) > this.recevedMessages[id]) {
                delete this.recevedMessages[id];
            }
        }
    }
    _cleanupKnownPeers() {
        for (const peer in this.knownPeers) {
            if (Math.floor(Date.now() / 1000) > this.knownPeers[peer][2]) {
                this._markPeerAsDead(peer);
            }
        }
    }
    _checkIfBroadcast(buf) {
        if (typeof buf === 'string') buf = Buffer.from(buf, 'hex');
        for (let i = 0; i < buf.length; i++) if (buf[i] !== 0xFF) return false;
        return true;
    }
    _markPeerAsDead(peer) {
        delete this.knownPeers[peer];
    }
    _encodeMessage(recipient, message, payload = new Uint8Array(0)) {
        if (typeof recipient === 'string') recipient = Buffer.from(recipient, 'hex');
        const version = Buffer.alloc(4);
        version.writeUInt32BE(1); // For later use
        const id = this._genId();
        const idString = id.toString('hex');
        const msg = Buffer.alloc(4);
        msg.writeUInt32BE(message);
        return { id, idString, buffer: Buffer.concat([version, id, recipient, this.crypto.publicKeyRaw, msg, payload]) };
    }
    _decodeMessage(data) {
        // 4b version + 8b id + 32b recipient + 1568b sender public key + 4b message + payload
        if (data.length < 1616) throw new Error('Invalid message size');
        let offset = 0;
        const version = data.readUInt32BE(offset);
        offset += 4;
        if (version !== 1) throw new Error('Unknown message version');
        const id = data.subarray(offset, offset + 8);
        offset += 8;
        const idString = id.toString('hex');
        const recipient = data.subarray(offset, offset + 32);
        offset += 32;
        const recipientString = recipient.toString('hex');
        const senderPubKey = data.subarray(offset, offset + 1568);
        offset += 1568;
        const senderIdentity = this.crypto.hash(senderPubKey, 'sha3-256');
        const senderIdentityString = senderIdentity.toString('hex');
        const message = data.readUInt32BE(offset);
        offset += 4;
        const encryptedPayload = data.subarray(offset);
        return { version, id, idString, recipient, recipientString, senderPubKey, senderIdentity, senderIdentityString, message, encryptedPayload };
    }
    async locate(identity) {
        const start = Date.now();
        while (!this.knownPeers[identity]) {
            if (this.locateTimeout !== 0 && Date.now() - start > this.locateTimeout) throw new Error('Locate timed out');
            for (const stream in this.streams) this.streams[stream].sendMessage(this._encodeMessage(identity, MESSAGES.PING).buffer);
            await new Promise(resolve => setTimeout(resolve, 500));
        }
        return true;
    }
    async ping(identity, timeout = 1000, trys = 1) {
        for (let i = 0; i < trys; i++) {
            try {
                if (!this.knownPeers[identity]) await this.locate(identity);
            } catch (e) {
                return false; // Peer not found
            }
            const message = this._encodeMessage(identity, MESSAGES.PING);
            this.streams[this.knownPeers[identity][0]].sendMessage(message.buffer);
            if (timeout > 0) setTimeout(() => { if (this._pingCBs[message.idString]) this._pingCBs[message.idString](1); }, timeout);
            const res = await new Promise(resolve => this._pingCBs[message.idString] = resolve);
            delete this._pingCBs[message.idString];
            if (res === 0) return true; // Success
            else if (res === 1) continue; // Timeout
        }
        this._markPeerAsDead(identity);
        return false;
    }
    async anounce(identity, data) {
        if (!this.knownPeers[identity]) await this.locate(identity);
        if (typeof data === 'string') data = Buffer.from(data);
        if (data.length > this.maxMessageSize) throw new Error('Message data too large');
        const message = this._encodeMessage(identity, MESSAGES.ANOUNCE, data.length > 0 ? this.crypto.encrypt(this.knownPeers[identity][1], data) : data);
        this.streams[this.knownPeers[identity][0]].sendMessage(message.buffer);
    }
    async query(identity, data, timeout = 0, trys = 1) {
        for (let i = 0; i < trys; i++) {
            if (!this.knownPeers[identity]) await this.locate(identity);
            if (typeof data === 'string') data = Buffer.from(data);
            if (data.length > this.maxMessageSize) throw new Error('Message data too large');
            const message = this._encodeMessage(identity, MESSAGES.QUERY, data.length > 0 ? this.crypto.encrypt(this.knownPeers[identity][1], data) : data);
            this.streams[this.knownPeers[identity][0]].sendMessage(message.buffer);
            if (timeout > 0) setTimeout(() => { if (this._queryCBs[message.idString]) this._queryCBs[message.idString]([1, 0, new Uint8Array(0)]); }, timeout);
            const [was_timeout, rstate, rdata] = await new Promise(resolve => this._queryCBs[message.idString] = resolve);
            delete this._queryCBs[message.idString];
            if (was_timeout === 0) return [rstate, rdata]; // Success
            else if (was_timeout === 1) throw new Error('Query timed out'); // Timeout
        }
    }
    async _sendQueryResponse(msg, message, data) {
        if (!this.knownPeers[msg.senderIdentityString]) await this.locate(msg.senderIdentityString);
        if (typeof data === 'string') data = Buffer.from(data);
        const response = this._encodeMessage(msg.senderIdentityString, message, this.crypto.encrypt(msg.senderPubKey, Buffer.concat([msg.id, data])));
        this.streams[this.knownPeers[msg.senderIdentityString][0]].sendMessage(response.buffer);
    }
    async sendDiscover() {
        for (const stream in this.streams) this.streams[stream].sendMessage(this._encodeMessage(this.broadcastIdentity, MESSAGES.DISCOVER).buffer);
    }
}

module.exports = QMProto;