const { WebSocketServer, WebSocket } = require('ws');
const crypto = require('node:crypto');

class WSConnection {
    constructor(socket, origin, address) {
        this.socket = socket;
        this.origin = origin;
        this.address = address;
        this.onMessage = (d) => { };
        this.onClose = () => { };
        this.socket.on('message', (d) => {
            if (d[0] === 0x0A) this.onMessage(d.subarray(1)); // message
        });
        this.socket.once('close', () => this.onClose());
    }

    isAlive() {
        return this.socket.readyState === 1;
    }

    sendMessage(message) {
        this.socket.send(Buffer.concat([new Uint8Array([0x0A]), message]));
    }

    close() {
        this.socket.close();
    }
}

class WSStream {
    constructor(qprotoInstance) {
        this.qproto = qprotoInstance;
        this.server = null;
        this.clients = [];
        this.clientReconnectTimeout = 3000;
    }
    enableServer(bindAddress = '0.0.0.0', bindPort = 8000) {
        if (this.isServerEnabled()) return;
        this.server = new WebSocketServer({ port: bindPort, host: bindAddress });
        this.server.on('connection', (ws, req) => this.qproto._onNewStream(new WSConnection(ws), { origin: 'server', ip: req.socket.remoteAddress, port: req.socket.remotePort }));
    }
    disableServer() {
        if (!this.isServerEnabled()) return;
        this.server.close();
        this.server = null;
    }
    isServerEnabled() {
        return this.server !== null;
    }
    addConnection(server) {
        const key = server.split('://')[1];
        const ip = key.split(':')[0];
        const port = key.split(':')[1] || (server.startsWith('wss://') ? 443 : 80);
        if (this.clients[key]) return false;
        this.clients[key] = {
            server,
            socket: new WebSocket(server)
        };
        this.clients[key].socket.on('error', (e) => { });
        this.clients[key].socket.once('close', () => {
            this.removeConnection(key);
            setTimeout(() => this.addConnection(server), this.clientReconnectTimeout);
        });
        this.clients[key].socket.once('open', (d) => {
            this.qproto._onNewStream(new WSConnection(this.clients[key].socket), { origin: 'client', ip, port });
        })
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

module.exports = WSStream;