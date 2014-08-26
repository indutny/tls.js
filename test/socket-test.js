var tls = require('..'),
    https = require('https'),
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
      var waiting = 2;

      var server = https.createServer(certs, function(req, res) {
        res.end('hello');
        req.socket.destroySoon();
        server.close(function() {
          if (--waiting === 0)
            done();
        });
      }).listen(PORT, function() {
        client = net.connect(PORT, onConnect);
      });

      function onConnect() {
        var s = tls.socket.create(client, ctx, 'client');
        s.start();
        s.end('GET / HTTP/1.1\r\n\r\n');

        var recv = '';
        s.on('data', function(d) {
          recv += d;
        });
        s.on('end', function() {
          assert(/200 OK/.test(recv));
          if (--waiting === 0)
            done();
        });
      }
    });
  });
});
