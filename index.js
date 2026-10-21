const QMProto = require('./src/main.js');
const WSStream = require('./stream-adapters/ws.js');
const TCPStream = require('./stream-adapters/tcp.js');

module.exports = { QMProto, StreamAdapters: { WSStream, TCPStream } };