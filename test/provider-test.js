var tls = require('..'),
    assert = require('assert');

var PORT = 8000;

describe('tls.js/Provider', function() {
  var provider = tls.provider.node.create();

  it('should create PRF', function() {
    var prf = new tls.utils.prf(provider.mac('sha256'))(
      new Buffer('1234'),
      new Buffer('label'),
      [ new Buffer('seed') ]);

    assert.equal(prf.read(256).length, 256);
  });

  it('should create SSL3Hash', function() {
    var ssl3hash = tls.utils.ssl3hash(provider)();

    ssl3hash.update('hello ');
    ssl3hash.update('world');

    var md5 = provider.hash('md5')();
    var sha1 = provider.hash('sha1')();

    assert.equal(ssl3hash.digest('hex'),
                 md5.update('hello world').digest('hex') +
                     sha1.update('hello world').digest('hex'));
  });
});
