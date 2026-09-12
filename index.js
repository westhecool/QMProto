const QMProto = require('./src/main.js');
const WSStream = require('./stream-adapters/ws.js');

module.exports = { QMProto, StreamAdapters: { WSStream } };