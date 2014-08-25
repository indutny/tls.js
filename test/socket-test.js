var tls = require('..'),
    ntls = require('tls'),
    net = require('net'),
    fs = require('fs'),
    assert = require('assert');

var PORT = 8000;

var certs = {
  key: fs.readFileSync(__dirname + '/keys/key.pem'),
  cert: fs.readFileSync(__dirname + '/keys/cert.pem')
};

describe('tls.js/Socket', function() {
  describe('ping/pong', function() {
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
      ctx.server.addKeyPair('rsa', certs);

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

    afterEach(function(done) {
      client.destroy();
      server.close(done);
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

  describe('interacting with OpenSSL', function() {
    var provider = tls.provider.node.create();
    var ctx = tls.context.create({ provider: provider });

    it('should connect to OpenSSL server', function(done) {
      var client;
      var server = ntls.createServer(certs, function(c) {
        c.destroy();
        server.close(done);
      }).listen(PORT, function() {
        client = net.connect(PORT, onConnect);
      });

      function onConnect() {
        var s = tls.socket.create(client, ctx, 'client');
        s.start();
      }
    });
  });
});
