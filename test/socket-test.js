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
  'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
  'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',
  'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384'
];

var version = [
  'tls1.2',
  'tls1.1',
  'tls1.0'
];

function all(fn) {
  version.forEach(function(version) {
    ciphers.forEach(function(cipher) {
      var info = tls.constants.cipherInfoByName[cipher];
      if (!info)
        throw new Error('Unknown cipher: ' + cipher);

      // Skip new ciphers on old tls versions
      if (version !== 'tls1.2' && info.version.min === 0x0303)
        return;

      describe('TLS version: ' + version + ' cipher: ' + cipher, function() {
        fn(version, cipher);
      });
    });
  });
}

describe('tls.js/Socket', function() {
  describe('ping/pong', function() {
    var server;
    var client;
    var serverSide;
    var clientSide;

    function runTest(version, cipher) {
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

        ctx.server.setVersion(version);
        ctx.server.setCiphers([ cipher ]);
        ctx.client.setVersion(version);
        ctx.client.setCiphers([ cipher ]);

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
    }

    all(runTest);
  });

  describe('interacting with OpenSSL', function() {
    var provider = tls.provider.node.create();

    function runTest(version, cipher) {
      it('should connect to OpenSSL server', function(done) {
        var ctx = tls.context.create({ provider: provider });
        var client;
        var waiting = 2;

        ctx.setVersion(version);
        ctx.setCiphers([ cipher ]);
        ctx.setMinVersion(version);
        ctx.setMaxVersion(version);

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

    all(runTest);
  });
});
