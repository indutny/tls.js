var tls = require('..'),
    https = require('https'),
    net = require('net'),
    fs = require('fs'),
    assert = require('assert');

var PORT = 8000;

var certs = {
  key: fs.readFileSync(__dirname + '/keys/key.pem'),
  cert: fs.readFileSync(__dirname + '/keys/cert.pem'),
  ciphers: 'ALL:NULL'
};

var ciphers = [
  'TLS_RSA_WITH_AES_256_CBC_SHA',
  'TLS_RSA_WITH_AES_128_CBC_SHA',
  'TLS_RSA_WITH_AES_256_CBC_SHA256',
  'TLS_RSA_WITH_AES_128_CBC_SHA256',
  'TLS_RSA_WITH_DES_CBC_SHA',
  'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
  'TLS_RSA_WITH_RC4_128_MD5',
  'TLS_RSA_WITH_RC4_128_SHA',
  'TLS_RSA_WITH_NULL_SHA',
  'TLS_RSA_WITH_IDEA_CBC_SHA',
  'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA'
];

describe('tls.js/Socket', function() {
  describe('ping/pong', function() {
    var server;
    var client;
    var serverSide;
    var clientSide;

    function testCipher(name) {
      describe(name + ' cipher', function() {
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

          ctx.server.setCiphers([ name ]);
          ctx.client.setCiphers([ name ]);

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
    }

    ciphers.forEach(testCipher);
  });

  describe('interacting with OpenSSL', function() {
    var provider = tls.provider.node.create();

    function testCipher(name) {
      it('should connect to OpenSSL server using ' + name, function(done) {
        var ctx = tls.context.create({ provider: provider });
        var client;
        var waiting = 2;

        ctx.setCiphers([ name ]);

        var server = https.createServer(certs, function(req, res) {
          res.end('hello');
          req.socket.end();
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
    }

    ciphers.forEach(testCipher);
  });
});
