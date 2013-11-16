var tls = require('..'),
    net = require('net'),
    assert = require('assert');

describe('tls.js/Parser', function() {
  var framer = null;
  var parser = null;

  beforeEach(function() {
    framer = tls.framer.create();
    parser = tls.parser.create();
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

    it('hello', function() {
      framer.hello('client', {
        cipherSuites: [
          tls.constants.cipherSuiteByName['TLS_ECDH_anon_WITH_AES_256_CBC_SHA']
        ]
      });
      var frame = parser.read();
      assert.equal(frame.type, 'handshake');
      assert.equal(frame.handshakeType, 'client_hello');
      assert(frame.random.time <= +new Date);
      assert.equal(frame.session, false);
      assert.equal(frame.compressions.length, 0);
      assert.equal(frame.cipherSuites.length, 1);
      assert.equal(frame.cipherSuites[0], 'TLS_ECDH_anon_WITH_AES_256_CBC_SHA');
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
  });
});
