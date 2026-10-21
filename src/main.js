const process = require('node:process');
if (!process.versions.openssl.startsWith('3.5.')) throw new Error(`[QMPROTO]: Missing OpenSSL version >= 3.5.0 (current: ${process.versions.openssl})`);
global.QMPROTO_DEBUG_FN = (...args) => { if (process.env.QMPROTO_DEBUG == 'true' || process.env.QMPROTO_DEBUG == '1') console.log('[QMPROTO-DEBUG]:', ...args); };
global.QMPROTO_ROUTER_DEBUG_FN = (...args) => { if (process.env.QMPROTO_ROUTER_DEBUG == 'true' || process.env.QMPROTO_ROUTER_DEBUG == '1') console.log('[QMPROTO-ROUTER-DEBUG]:', ...args); };
const Crypto = require('./crypto.js');
const { EventEmitter } = require('node:events');
const { MESSAGES } = require('./constants.js');

class QMProto extends EventEmitter {
    constructor({ keyDirectory, maxMessagePayloadSize, maxMessageForwardSize, sendHelloOnConnect, respondToBroadcastPing } = {}) {
        super();
        if (typeof maxMessagePayloadSize !== 'number') maxMessagePayloadSize = (20 * 1024 * 1024) + 4096; // 20MB + overhead for encryption
        if (typeof maxMessageForwardSize !== 'number') maxMessageForwardSize = (20 * 1024 * 1024) + 8192; // 20MB + overhead for proto & encryption
        if (typeof sendHelloOnConnect !== 'boolean') sendHelloOnConnect = true;
        if (typeof respondToBroadcastPing !== 'boolean') respondToBroadcastPing = true;

        this.maxMessagePayloadSize = maxMessagePayloadSize;
        this.maxMessageForwardSize = maxMessageForwardSize;
        this.sendHelloOnConnect = sendHelloOnConnect;
        this.respondToBroadcastPing = respondToBroadcastPing;

        this.crypto = new Crypto(keyDirectory);
        this.identity = this.crypto.publicKeyId;
        this.identityString = this.crypto.publicKeyIdString;

        this.knownPeersTTL = 300; // <<< Queries longer then 300s will fail!
        this.messagePacketTimeoutMS = 1000;

        this.streams = {};
        this.knownPeers = {};
        this.activeSessionRequestChallenges = {};
        this.broadcastIdentityString = Buffer.alloc(32).fill(0xFF).toString('hex');
        this.receivedMessages = {};
        this._messageCBs = {};

        this._cleanupInterval = setInterval(() => this._cleanupLoop(), 3000);
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
            this.streams[streamId] = stream;
            this.streams[streamId].onMessage = (data) => this._onRawMessage(streamId, data);
            this.streams[streamId].onClose = () => this._onStreamClose(streamId);
            if (this.sendHelloOnConnect) this.streams[streamId].sendMessage(this._encodeResponse(this.broadcastIdentityString, MESSAGES.HELLO, Buffer.alloc(8).fill(0xFF)).buffer);
        } catch (e) {
            QMPROTO_DEBUG_FN(`Error registering stream ${streamId}:`, e.message);
        }
    }

    _onStreamClose(streamId) {
        for (const peer in this.knownPeers) if (this.knownPeers[peer][0] === streamId) delete this.knownPeers[peer];
        delete this.streams[streamId];
    }

    _onRawMessage(streamId, data) {
        try {
            const msg = this._decodeMessage(data);
            if (msg.senderIdentityString === this.identityString) return; // Ignore our own messages that may have been forwarded back to us

            if (this.knownPeers[msg.senderIdentityString]) {
                if (this.knownPeers[msg.senderIdentityString][0] !== streamId) this.knownPeers[msg.senderIdentityString][0] = streamId; // Make sure the routing stream is up to date
                this.knownPeers[msg.senderIdentityString][1] = Math.floor(Date.now() / 1000); // Update last seen at
            } else {
                this.knownPeers[msg.senderIdentityString] = [streamId, Math.floor(Date.now() / 1000), null, null]; // StreamId, last seen at, active session key, active session hash
            }

            if (msg.code === MESSAGES.HELLO) this.emit('new-peer', msg, msg.senderIdentityString);

            // PING can be broadcast
            if ((msg.code === MESSAGES.PING) && (msg.recipientString === this.identityString || msg.recipientString === this.broadcastIdentityString)) {
                this.emit('ping', msg, msg.senderIdentityString);
                if ((msg.recipientString === this.identityString) || (msg.recipientString === this.broadcastIdentityString && this.respondToBroadcastPing)) this.streams[streamId].sendMessage(this._encodeResponse(msg.senderIdentity, MESSAGES.PONG, msg.id).buffer);
            }

            if (msg.recipientString === this.identityString) {
                if (this.receivedMessages[msg.idString]) return; // Ignore duplicate messages
                this.receivedMessages[msg.idString] = Math.floor(Date.now() / 1000) + 5;

                if (msg.payload.length > this.maxMessagePayloadSize) {
                    QMPROTO_DEBUG_FN(`Dropping message with payload too large (${msg.payload.length} bytes > max ${this.maxMessagePayloadSize} bytes)`);
                    return;
                }

                if (msg.type === 0) { // Requests
                    switch (msg.code) {
                        case MESSAGES.REQUEST_PUBKEY:
                            this.streams[streamId].sendMessage(this._encodeResponse(msg.senderIdentity, MESSAGES.PUBKEY, msg.id, this.crypto.publicKeyRaw).buffer);
                            break;
                        case MESSAGES.SESSION_INIT_STAGE1:
                            // 1568b sender pub key + 1568b hmac key cipher + 32b seed
                            if (!msg.payload || msg.payload.length !== 3168) return; // Invalid request

                            QMPROTO_DEBUG_FN(`{SESSION} [${msg.senderIdentityString.substring(0, 16)}] Requested a new session. Solving their challenge and sending our one back.`);

                            const senderPubKey = msg.payload.subarray(0, 1568);
                            if (!this.crypto.timingSafeEqual(this.crypto.hash(senderPubKey), msg.senderIdentity)) return; // Someone is up to no good

                            const requestChallengeResponse = this.crypto.solveChallenge(msg.payload.subarray(1568));
                            const { expectedResponse, challengeBuffer: newChallengeBuffer } = this.crypto.createChallenge(senderPubKey);

                            this.activeSessionRequestChallenges[msg.senderIdentityString] = [Math.floor(Date.now() / 1000) + 5, expectedResponse];

                            this.streams[streamId].sendMessage(this._encodeResponse(msg.senderIdentity, MESSAGES.SESSION_INIT_STAGE1_RESPONSE, msg.id, Buffer.concat([requestChallengeResponse, newChallengeBuffer])).buffer);
                            break;
                        case MESSAGES.SESSION_INIT_STAGE2:
                            // 1568b sender pub key + 32b challenge response
                            if (!msg.payload || msg.payload.length !== 1600) return; // Invalid request

                            const senderPubKey2 = msg.payload.subarray(0, 1568);
                            if (!this.crypto.timingSafeEqual(this.crypto.hash(senderPubKey2), msg.senderIdentity)) return; // Someone is up to no good

                            const challengeResponse = msg.payload.subarray(1568);

                            if (this.activeSessionRequestChallenges[msg.senderIdentityString] && this.crypto.timingSafeEqual(this.activeSessionRequestChallenges[msg.senderIdentityString][1], challengeResponse)) {
                                delete this.activeSessionRequestChallenges[msg.senderIdentityString];
                                QMPROTO_DEBUG_FN(`{SESSION} [${msg.senderIdentityString.substring(0, 16)}] Solved our challenge successfully. Granting new session.`);
                                const sessionKey = this.crypto.randomBytes(32);
                                this.knownPeers[msg.senderIdentityString][2] = sessionKey; // Update current session key
                                this.knownPeers[msg.senderIdentityString][3] = this.crypto.hash(sessionKey); // Update current session hash
                                this.streams[streamId].sendMessage(this._encodeResponse(msg.senderIdentity, MESSAGES.SESSION_INFO, msg.id, this.crypto.PKIEncrypt(senderPubKey2, sessionKey)).buffer);
                            } else {
                                QMPROTO_DEBUG_FN(`{SESSION} [${msg.senderIdentityString.substring(0, 16)}] Failed our challenge!`);
                                this.streams[streamId].sendMessage(this._encodeResponse(msg.senderIdentity, MESSAGES.SESSION_INVALID, msg.id).buffer);
                            }
                            break;
                        case MESSAGES.QUERY:
                            if (this.knownPeers[msg.senderIdentityString][2] !== null && this.knownPeers[msg.senderIdentityString][3].equals(msg.payload.subarray(0, 32))) { // Check if session hash matches or not
                                const payload = this.crypto.AESDecrypt(this.knownPeers[msg.senderIdentityString][2], msg.payload.subarray(32));
                                this.streams[streamId].sendMessage(this._encodeResponse(msg.senderIdentity, MESSAGES.ACKNOWLEDGED, msg.id).buffer);
                                this.emit('query', msg, msg.senderIdentityString, payload, async (data = new Uint8Array(0)) => await this._sendQueryResponse(streamId, msg, MESSAGES.QUERY_SUCCESS, data), async (data = new Uint8Array(0)) => await this._sendQueryResponse(streamId, msg, MESSAGES.QUERY_FAILURE, data), async (data = new Uint8Array(0)) => await this._sendQueryResponse(streamId, msg, MESSAGES.QUERY_REFUSED, data));
                            } else {
                                this.streams[streamId].sendMessage(this._encodeResponse(msg.senderIdentity, MESSAGES.SESSION_INVALID, msg.id).buffer);
                            }
                            break;
                    }
                } else if (msg.type === 1) { // Responses
                    switch (msg.code) {
                        case MESSAGES.PONG:
                            this.emit('pong', msg, msg.senderIdentityString);
                            break;
                    }

                    if (this._messageCBs[msg.requestIdString]) this._messageCBs[msg.requestIdString]([msg.code, msg.payload]); // Hand back the message to the function that issued the request
                }
            } else {
                if (data.length > this.maxMessageForwardSize) {
                    QMPROTO_ROUTER_DEBUG_FN(`Dropping message to forward that is too large (${data.length} bytes > max ${this.maxMessageForwardSize} bytes)`);
                    return;
                }
                QMPROTO_ROUTER_DEBUG_FN(`Forwarding message [${msg.idString}] ${msg.senderIdentityString.substring(0, 16)} -> ${msg.recipientString.substring(0, 16)} (${data.length}b)`)
                this._send(msg.recipientString, data, streamId); // Don't forward the message back to the sender stream
            }
        } catch (e) {
            QMPROTO_DEBUG_FN('Error decoding incoming message:', e.message);
        }
    }

    async _sendQueryResponse(streamId, msg, message, data) {
        if (!this.knownPeers[msg.senderIdentityString]) throw new Error('Unable to send response: peer is unknown.');
        if (this.knownPeers[msg.senderIdentityString][2] === null) throw new Error('Unable to send response: peer session is unknown.');
        if (typeof data === 'string') data = Buffer.from(data);
        const res_data = this.crypto.AESEncrypt(this.knownPeers[msg.senderIdentityString][2], data);
        this.streams[streamId].sendMessage(this._encodeResponse(msg.senderIdentity, message, msg.id, res_data).buffer);
    }

    _cleanupLoop() {
        for (const id in this.activeSessionRequestChallenges) if (Math.floor(Date.now() / 1000) > this.activeSessionRequestChallenges[id][0]) delete this.receivedMessages[id];
        for (const id in this.receivedMessages) if (Math.floor(Date.now() / 1000) > this.receivedMessages[id]) delete this.receivedMessages[id]; // TODO: NEEDS WORK
        for (const peer in this.knownPeers) if (Math.floor(Date.now() / 1000) > (this.knownPeers[peer][1] + this.knownPeersTTL)) delete this.knownPeers[peer];
    }

    _encodeRequest(recipient, code, payload = new Uint8Array(0)) {
        if (typeof recipient === 'string') recipient = Buffer.from(recipient, 'hex');

        const version = Buffer.alloc(4);
        version.writeUInt32BE(1); // For later use

        const id = this._genId();
        const idString = id.toString('hex');

        const codeBuf = Buffer.alloc(4);
        codeBuf.writeUInt32BE(code);

        return { id, idString, buffer: Buffer.concat([version, id, recipient, this.identity, codeBuf, payload]) };
    }

    _encodeResponse(recipient, code, requestId, payload = new Uint8Array(0)) {
        if (typeof recipient === 'string') recipient = Buffer.from(recipient, 'hex');
        if (typeof requestId === 'string') requestId = Buffer.from(requestId, 'hex');

        const version = Buffer.alloc(4);
        version.writeUInt32BE(1); // For later use

        const id = this._genId();
        const idString = id.toString('hex');

        const codeBuf = Buffer.alloc(4);
        codeBuf.writeUInt32BE(code);

        return { id, idString, buffer: Buffer.concat([version, id, recipient, this.identity, codeBuf, requestId, payload]) };
    }

    _decodeMessage(data) {
        // 4b version + 8b id + 32b recipient + 32b sender + 4b message [+ 8b request id] + data
        if (data.length < 80) throw new Error('Invalid message size.');
        let type = 0;
        let offset = 0;

        const version = data.readUInt32BE(offset);
        if (version !== 1) throw new Error('Unknown message version.');
        offset += 4;

        const id = data.subarray(offset, offset + 8);
        const idString = id.toString('hex');
        offset += 8;

        const recipient = data.subarray(offset, offset + 32);
        const recipientString = recipient.toString('hex');
        offset += 32;

        const senderIdentity = data.subarray(offset, offset + 32);
        const senderIdentityString = senderIdentity.toString('hex');
        offset += 32;

        const code = data.readUInt32BE(offset);
        offset += 4;

        let requestId = null, requestIdString = null;
        if (code >= 1_000_000 && code < 2_000_000) { // Response
            type = 1;
            requestId = data.subarray(offset, offset + 8);
            requestIdString = requestId.toString('hex');
            offset += 8;
        }

        const payload = data.subarray(offset);

        return { version, type, id, idString, requestId, requestIdString, recipient, recipientString, senderIdentity, senderIdentityString, code, payload };
    }

    _send(identity, data, skip = null) {
        if (this.knownPeers[identity] && identity !== this.broadcastIdentityString) {
            this.streams[this.knownPeers[identity][0]].sendMessage(data);
        } else {
            for (const streamId in this.streams) {
                if (skip !== null && streamId === skip) continue;
                this.streams[streamId].sendMessage(data);
            }
        }
    }

    async _sendAndWait(identity, message, res_timeout = 30000, ack_timeout = 10000) {
        let res_elapsed = 0;
        let ack_elapsed = 0;
        let res_received = false;
        let ack_received = false;
        let res = null;
        let cb = null;

        this._messageCBs[message.idString] = ([res_message, res_data]) => {
            res = [res_message, res_data];
            if (res_message === MESSAGES.ACKNOWLEDGED) ack_received = true;
            else res_received = true;
            if (typeof cb === 'function') cb();
        };

        while (true) {
            setImmediate(async () => {
                while (true) {
                    let ack_wait = !ack_received;
                    try {
                        if (!ack_received) this._send(identity, message.buffer);
                    } catch (e) { }

                    await new Promise((r) => setTimeout(r, this.messagePacketTimeoutMS));
                    if (res_received || (ack_wait && ack_received)) break;

                    if (!ack_received) {
                        ack_elapsed += this.messagePacketTimeoutMS;
                        if (ack_timeout > 0 && ack_elapsed >= ack_timeout && this._messageCBs[message.idString]) {
                            this._messageCBs[message.idString]([-1, null]);
                            break;
                        }
                    } else {
                        res_elapsed += this.messagePacketTimeoutMS;
                        if (res_timeout > 0 && res_elapsed >= res_timeout && this._messageCBs[message.idString]) {
                            this._messageCBs[message.idString]([-1, null]);
                            break;
                        }
                    }
                }
            });

            if (!res_received) await new Promise(r => cb = r);

            if (res[0] === -1) { // Timeout
                delete this._messageCBs[message.idString];
                if (!ack_received) {
                    throw new Error('Timeout waiting for request acknowledgement from peer.');
                } else {
                    throw new Error('Timeout waiting for response from peer.');
                }
            } else if (res[0] !== MESSAGES.ACKNOWLEDGED) {
                delete this._messageCBs[message.idString];
                return res;
            }
        }
    }

    async requestSession(identity, timeout = 6000) {
        if (typeof identity !== 'string') throw new Error('Identity is required.');

        if (!(await this.ping(identity, timeout))) throw new Error('Failed to ping peer.');

        const peerPubKey = await this.requestPublicKey(identity, timeout);
        const peerIdentityString = this.crypto.hash(peerPubKey).toString('hex');

        QMPROTO_DEBUG_FN(`{SESSION} Requesting new session from [${peerIdentityString.substring(0, 16)}].`);

        const { expectedResponse, challengeBuffer } = this.crypto.createChallenge(peerPubKey);

        const message = this._encodeRequest(identity, MESSAGES.SESSION_INIT_STAGE1, Buffer.concat([this.crypto.publicKeyRaw, challengeBuffer]));
        const [res_message, res_data] = await this._sendAndWait(identity, message, timeout, timeout);
        if (res_message !== MESSAGES.SESSION_INIT_STAGE1_RESPONSE) throw new Error('Received bad response code.');
        // 32b challenge response + new challenge for us (1568b hmac key cipher + 32b seed)
        if (res_data.length < 1632) throw new Error('Received bad response data.');

        const receivedResponse = res_data.subarray(0, 32);
        const valid = (expectedResponse.length === receivedResponse.length) && this.crypto.timingSafeEqual(expectedResponse, receivedResponse);

        if (valid) {
            QMPROTO_DEBUG_FN(`{SESSION} [${peerIdentityString.substring(0, 16)}] Solved our challenge successfully. Now solving their challenge and sending it back.`);

            const challengeResponse = this.crypto.solveChallenge(res_data.subarray(32));

            const message2 = this._encodeRequest(identity, MESSAGES.SESSION_INIT_STAGE2, Buffer.concat([this.crypto.publicKeyRaw, challengeResponse]));
            const [res_message2, res_data2] = await this._sendAndWait(identity, message2, timeout, timeout);
            if (res_message2 !== MESSAGES.SESSION_INFO) throw new Error('Received bad response code.');
            // Encrypted new session key (1568b shared key + 12b iv + cipherText + 16b auth tag)
            if (res_data2.length <= 1596) throw new Error('Received bad response data.');

            const sessionKey = this.crypto.PKIDecrypt(res_data2);

            QMPROTO_DEBUG_FN(`{SESSION} Successfully got a new session from [${peerIdentityString.substring(0, 16)}].`);

            this.knownPeers[identity][2] = sessionKey; // Update current session key
            this.knownPeers[identity][3] = this.crypto.hash(sessionKey); // Update current session hash

            return true;
        } else {
            QMPROTO_DEBUG_FN(`{SESSION} [${peerIdentityString.substring(0, 16)}] Failed our challenge!`);
            throw new Error('Remote peer failed our challenge!');
        }
    }

    async requestPublicKey(identity, timeout = 6000) {
        if (typeof identity !== 'string') throw new Error('Identity is required.');
        const message = this._encodeRequest(identity, MESSAGES.REQUEST_PUBKEY);
        const [res_message, res_data] = await this._sendAndWait(identity, message, timeout, timeout);
        if (res_message !== MESSAGES.PUBKEY) throw new Error('Received bad response code.');
        if (!this.crypto.timingSafeEqual(this.crypto.hash(res_data), Buffer.from(identity, 'hex'))) throw new Error('Peer sent a key that does not match their identity!'); // Someone is up to no good
        return res_data;
    }

    async sendBroadcastPing() {
        const message = this._encodeRequest(this.broadcastIdentityString, MESSAGES.PING);
        this._send(this.broadcastIdentityString, message.buffer);
    }

    async ping(identity, timeout = 1000) {
        if (typeof identity !== 'string') throw new Error('Identity is required.');
        const message = this._encodeRequest(identity, MESSAGES.PING);
        try {
            const [res_message, res_data] = await this._sendAndWait(identity, message, timeout, timeout);
            if (res_message !== MESSAGES.PONG) throw new Error('Received bad response code.');
            return true;
        } catch (e) { }
        delete this.knownPeers[identity]; // Mark the peer as dead
        return false;
    }

    async query(identity, data, res_timeout = 30000, ack_timeout = 10000) {
        if (typeof identity !== 'string') throw new Error('Identity is required.');
        if (!data || data.length < 0) throw new Error('Data is required.');
        if (typeof data === 'string') data = Buffer.from(data, 'utf-8');
        if (!this.knownPeers[identity] || this.knownPeers[identity][2] === null) await this.requestSession(identity);
        let triedNewSession = false;
        while (true) {
            const payload = this.crypto.AESEncrypt(this.knownPeers[identity][2], data);
            const message = this._encodeRequest(identity, MESSAGES.QUERY, Buffer.concat([this.knownPeers[identity][3], payload]));
            const [res_message, res_data] = await this._sendAndWait(identity, message, res_timeout, ack_timeout);
            let result_data = null;
            if (res_data.length > 0) result_data = this.crypto.AESDecrypt(this.knownPeers[identity][2], res_data);
            switch (res_message) {
                case MESSAGES.SESSION_INVALID:
                    if (triedNewSession) throw new Error('Failed to get a vaild session with the peer!');
                    await this.requestSession(identity);
                    triedNewSession = true;
                    break;
                case MESSAGES.QUERY_REFUSED:
                    return [-1, result_data];
                    break;
                case MESSAGES.QUERY_FAILURE:
                    return [0, result_data];
                    break;
                case MESSAGES.QUERY_SUCCESS:
                    return [1, result_data];
                    break;
                default:
                    throw new Error(`Received bad status code from peer: ${res_message}`);
                    break;
            }
        }
    }
}

module.exports = QMProto;