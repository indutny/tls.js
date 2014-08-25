var tls = require('..'),
    assert = require('assert');

var PORT = 8000;

describe('tls.js/Provider', function() {
  var provider = tls.provider.node.create();

  it('should create PRF', function() {
    var prf = new provider.prf('sha256')(
      new Buffer('1234'),
      new Buffer('label'),
      new Buffer('seed'));

    assert.equal(prf.read(256).length, 256);
  });
});
