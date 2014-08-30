var tls = require('..'),
    net = require('net'),
    assert = require('assert');

describe('tls.js/Framer', function() {
  var framer = null;
  var parser = null;
  var provider = tls.provider.node.create();

  beforeEach(function() {
    var state = tls.state.createDummy({ provider: provider });
    framer = tls.framer.create(state);
    parser = tls.parser.create(state);
    framer.pipe(parser);
  });

  describe('should gen and parse', function() {
    it('change cipher spec', function() {
      framer.changeCipherSpec();
      var frame = parser.read();
      assert.equal(frame.type, 'change_cipher_spec');
    });

    it('alert', function() {
      framer.alert('fatal', 'illegal_parameter');
      var frame = parser.read();
      assert.equal(frame.type, 'alert');
      assert.equal(frame.level, 'fatal');
      assert.equal(frame.description, 'illegal_parameter');
    });

    it('client_hello', function() {
      framer.hello('client', {
        cipherSuites: [
          'TLS_ECDH_anon_WITH_AES_256_CBC_SHA'
        ],
        compressionMethods: ['null', 'deflate'],
        extensions: [
          {
            type: 'next_protocol_negotiation',
            body: new Buffer(0)
          }
        ]
      });
      var frame = parser.read();
      assert.equal(frame.type, 'handshake');
      assert.equal(frame.handshakeType, 'client_hello');
      assert.equal(frame.random.length, 32);
      assert.equal(frame.session, false);
      assert.equal(frame.cipherSuites.length, 1);
      assert.equal(frame.cipherSuites[0], 'TLS_ECDH_anon_WITH_AES_256_CBC_SHA');
      assert.equal(frame.compressionMethods.length, 2);
      assert.equal(frame.compressionMethods[0], 'null');
      assert.equal(frame.compressionMethods[1], 'deflate');
      assert.equal(frame.extensions.next_protocol_negotiation.size, 0);
    });

    it('server_hello', function() {
      framer.hello('server', {
        cipherSuite: 'TLS_ECDH_anon_WITH_AES_256_CBC_SHA',
        compressionMethod: 'deflate'
      });
      var frame = parser.read();
      assert.equal(frame.type, 'handshake');
      assert.equal(frame.handshakeType, 'server_hello');
      assert.equal(frame.random.length, 32);
      assert.equal(frame.session, false);
      assert.equal(frame.cipherSuite, 'TLS_ECDH_anon_WITH_AES_256_CBC_SHA');
      assert.equal(frame.compressionMethod, 'deflate');
    });

    it('certificate', function() {
      framer.certificate([
        new Buffer('hello')
      ]);
      var frame = parser.read();
      assert.equal(frame.type, 'handshake');
      assert.equal(frame.handshakeType, 'certificate');
      assert.equal(frame.certs.length, 1);
      assert.equal(frame.certs[0].toString(), 'hello');
    });

    it('certificate_request', function() {
      framer.certificateRequest({
        types: [ 'rsa_fixed_dh' ],
        signatureAlgorithms: [
          { hash: 'sha1', sign: 'rsa' }
        ],
        authorities: [ new Buffer('der') ]
      });
      var frame = parser.read();
      assert.equal(frame.type, 'handshake');
      assert.equal(frame.handshakeType, 'certificate_request');
      assert.equal(frame.types.length, 1);
      assert.equal(frame.types[0], 'rsa_fixed_dh');
      assert.equal(frame.signatureAlgorithms.length, 1);
      assert.deepEqual(frame.signatureAlgorithms[0], {
        hash: 'sha1',
        sign: 'rsa'
      });
      assert.equal(frame.authorities.length, 1);
      assert.equal(frame.authorities[0].toString(), 'der');
    });

    it('server_hello_done', function() {
      framer.helloDone();
      var frame = parser.read();
      assert.equal(frame.type, 'handshake');
      assert.equal(frame.handshakeType, 'server_hello_done');
    });

    it('hello_request', function() {
      framer.helloRequest();
      var frame = parser.read();
      assert.equal(frame.type, 'handshake');
      assert.equal(frame.handshakeType, 'hello_request');
    });

    it('finished', function() {
      framer.finished(new Buffer('hello'));
      var frame = parser.read();
      assert.equal(frame.type, 'handshake');
      assert.equal(frame.handshakeType, 'finished');
      assert.equal(frame.verify.toString(), 'hello');
    });

    it('client_key_exchange', function() {
      framer.keyExchange('client', new Buffer('hello'));
      var frame = parser.read();
      assert.equal(frame.type, 'handshake');
      assert.equal(frame.handshakeType, 'client_key_exchange');
      assert.equal(frame.content.toString(), 'hello');
    });

    it('server_key_exchange', function() {
      framer.keyExchange('server', new Buffer('hello'));
      var frame = parser.read();
      assert.equal(frame.type, 'handshake');
      assert.equal(frame.handshakeType, 'server_key_exchange');
      assert.equal(frame.content.toString(), 'hello');
    });
  });
});
