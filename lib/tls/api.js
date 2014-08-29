var net = require('net');
var http = require('http');
var util = require('util');
var tls = require('../tls');

function Server(options, listener) {
  net.Server.call(this, this._onTLSConnection);

  var provider = tls.provider.node.create();

  this.context = tls.context.create({ provider: provider });
  this.context.addKeyPair('rsa', { key: options.key, cert: options.cert });

  if (options.ciphers)
    this.context.setCiphers(options.ciphers);
  if (options.version)
    this.context.setVersion(options.version);

  if (listener)
    this.on('secureConnection', listener);
}
util.inherits(Server, net.Server);
exports.Server = Server;

exports.createServer = function createServer(options, listener) {
  return new Server(options, listener);
};

Server.prototype._onTLSConnection = function _onTLSConnection(c) {
  var self = this;
  var tc = tls.socket.create(c, this.context, 'server');
  tc.start();

  tc.on('secure', function() {
    tc.removeListener('error', ignoreError);
    self.emit('secureConnection', tc);
  });

  function ignoreError() {
    // Just ignore
  }
  tc.on('error', ignoreError);
};

function HTTPServer(options, listener) {
  Server.call(this, options, http._connectionListener);

  if (listener)
    this.on('request', listener);
}
util.inherits(HTTPServer, Server);
exports.HTTPServer = HTTPServer;

exports.createHTTPServer = function createHTTPServer(options, listener) {
  return new HTTPServer(options, listener);
};
