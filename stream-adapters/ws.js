const { WebSocketServer, WebSocket } = require('ws');

class WSConnection {
    constructor(socket, origin) {
        this.socket = socket;
        this.origin = origin;
        this.onMessage = (data) => { };
        this.onClose = () => { };
        this.socket.on('message', (data) => this.onMessage(data));
        this.socket.once('close', () => this.onClose());
    }

    isAlive() {
        return this.socket.readyState === 1;
    }

    sendMessage(data) {
        this.socket.send(data);
    }

    close() {
        this.socket.close();
    }
}

class WSStream {
    constructor(qmprotoInstance) {
        this.qmproto = qmprotoInstance;
        this.servers = [];
        this.clients = [];
        this.clientReconnectTimeout = 2000;
    }

    enableServer(bindAddress = '0.0.0.0', bindPort = 8000) {
        const key = `${bindAddress}:${bindPort}`;
        if (this.servers[key]) return;
        this.servers[key] = new WebSocketServer({ port: bindPort, host: bindAddress });
        this.servers[key].on('connection', (ws, req) => {
            ws.on('error', (e) => { });
            this.qmproto._onNewStream(new WSConnection(ws), { relation: 'client', host: req.socket.remoteAddress, port: req.socket.remotePort });
        });
    }

    disableServer(bindAddress = '0.0.0.0', bindPort = 8000) {
        const key = `${bindAddress}:${bindPort}`;
        if (!this.servers[key]) return false;
        this.servers[key].close();
        delete this.servers[key];
        return true;
    }

    isServerEnabled(bindAddress = '0.0.0.0', bindPort = 8000) {
        const key = `${bindAddress}:${bindPort}`;
        return Boolean(this.servers[key]);
    }

    addConnection(server) {
        const proto = server.split('://')[0];
        if (proto !== 'ws' && proto !== 'wss') throw new Error('Invalid protocol!');
        const key = server.split('://')[1];
        const host = key.split(':')[0];
        const port = parseInt(key.split(':')[1] || ((proto === 'wss') ? 443 : 80));
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
        this.clients[key].socket.once('open', () => {
            this.qmproto._onNewStream(new WSConnection(this.clients[key].socket), { relation: 'server', host, port });
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