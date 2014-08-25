var tls = require('..'),
    net = require('net'),
    fs = require('fs'),
    assert = require('assert');

var PORT = 8000;

describe('tls.js/Socket', function() {
  var server;
  var client;
  var serverSide;
  var clientSide;

  beforeEach(function(done) {
    var waiting = 2;
    function wait() {
      if (--waiting === 0) done();
    }

    var provider = tls.provider.node.create();
    var ctx = {
      client: tls.context.create({ provider: provider }),
      server: tls.context.create({ provider: provider })
    };
    ctx.server.addKeyPair('rsa', {
      key: fs.readFileSync(__dirname + '/keys/key.pem'),
      cert: fs.readFileSync(__dirname + '/keys/cert.pem')
    });

    server = net.createServer(function(socket) {
      serverSide = tls.socket.create(socket, ctx.server, 'server');
      serverSide.start();
      wait();
    }).listen(PORT, function() {
      client = net.connect(PORT, function() {
        clientSide = tls.socket.create(client, ctx.client, 'client');
        clientSide.start();
        wait();
      });
    });
  });

  it('should establish secure connection', function(done) {
    var waiting = 2;
    function wait() {
      if (--waiting === 0) done();
    }
    serverSide.on('secure', wait);
    clientSide.on('secure', wait);
  });
});
