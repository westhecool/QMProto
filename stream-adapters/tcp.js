const net = require('node:net');

class TCPConnection {
    constructor(socket, origin) {
        this.socket = socket;
        this.origin = origin;
        this.onMessage = (data) => { };
        this.onClose = () => { };

        this.maxMessageSize = 100 * 1024 * 1024;
        this.readTimeOut = 4000;

        this._reading = false;
        this._lastRead = 0;
        this._readSize = 0;
        this._readOffset = 0;
        this._currentBuffer = null;
        this.socket.on('data', (d) => {
            try {
                this._lastRead = performance.now();
                let data = d;

                if (this._reading) {
                    const remaining = this._readSize - this._readOffset;
                    if (data.length <= remaining) {
                        this._currentBuffer.push(data);
                        this._readOffset += data.length;
                        data = null;
                    } else {
                        this._currentBuffer.push(data.subarray(0, remaining));
                        this._readOffset += remaining;
                        data = data.subarray(remaining);
                    }
                    if (this._readOffset === this._readSize) this._processMessage();
                }

                if (!this._reading) {
                    if (!data || data.length <= 4) return;
                    const rs = data.readUint32BE();
                    if (rs <= 0 || rs > this.maxMessageSize) return;
                    this._readSize = rs;
                    this._currentBuffer = [data.subarray(4)];
                    this._readOffset = data.length - 4;
                    this._reading = true;
                    if (this._readOffset === this._readSize) this._processMessage();
                }
            } catch (e) { }
        });

        this.socket.once('close', () => {
            this.onClose();
            clearInterval(this._timeoutWatcherInterval);
        });

        this._timeoutWatcherInterval = setInterval(() => this._timeoutWatcher(), 1000);
    }

    _resetRead() {
        this._readSize = 0;
        this._readOffset = 0;
        this._currentBuffer = null;
        this._reading = false;
    }

    _processMessage() {
        const m = Buffer.concat(this._currentBuffer);
        this.onMessage(m);
        this._resetRead();
    }

    _timeoutWatcher() {
        if (this._reading && ((performance.now() - this._lastRead)) >= this.readTimeOut) this._resetRead(); // TODO: NEEDS WORK
    }

    isAlive() {
        return this.socket.readyState === 'open';
    }

    sendMessage(data) {
        const len = Buffer.alloc(4);
        len.writeUint32BE(data.length);
        this.socket.write(Buffer.concat([len, data]));
    }

    close() {
        this.socket.destroy();
    }
}

class TCPStream {
    constructor(qmprotoInstance) {
        this.qmproto = qmprotoInstance;
        this.servers = [];
        this.clients = [];
        this.clientReconnectTimeout = 2000;
    }

    enableServer(bindAddress = '0.0.0.0', bindPort = 8001) {
        const key = `${bindAddress}:${bindPort}`;
        if (this.servers[key]) return;
        this.servers[key] = net.createServer((socket) => {
            socket.on('error', (e) => { });
            this.qmproto._onNewStream(new TCPConnection(socket), { relation: 'client', host: socket.remoteAddress, port: socket.remotePort });
        });
        this.servers[key].listen(bindPort, bindAddress);
    }

    disableServer(bindAddress = '0.0.0.0', bindPort = 8001) {
        const key = `${bindAddress}:${bindPort}`;
        if (!this.servers[key]) return false;
        this.servers[key].close(); // TODO: Needs work. TCP server has no client clean up.
        delete this.servers[key];
        return true;
    }

    isServerEnabled(bindAddress = '0.0.0.0', bindPort = 8001) {
        const key = `${bindAddress}:${bindPort}`;
        return Boolean(this.servers[key]);
    }

    addConnection(server) {
        const proto = server.split('://')[0];
        if (proto !== 'tcp') throw new Error('Invalid protocol!');
        const key = server.split('://')[1];
        const host = key.split(':')[0];
        const port = parseInt(key.split(':')[1]);
        if (this.clients[key]) return false;
        this.clients[key] = {
            server,
            socket: new net.Socket()
        };
        this.clients[key].socket.on('error', (e) => { });
        this.clients[key].socket.once('close', () => {
            this.removeConnection(key);
            setTimeout(() => this.addConnection(server), this.clientReconnectTimeout);
        });
        this.clients[key].socket.once('connect', () => {
            this.qmproto._onNewStream(new TCPConnection(this.clients[key].socket), { relation: 'server', host, port });
        });
        this.clients[key].socket.connect({ host, port });
        return true;
    }

    removeConnection(server) {
        if (!this.clients[server]) return false;
        try {
            this.clients[server].socket.destroy();
        } catch (e) { }
        delete this.clients[server];
        return true;
    }
}

module.exports = TCPStream;