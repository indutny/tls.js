var tls = require('..'),
    assert = require('assert');

var PORT = 8000;

describe('tls.js/Utils', function() {
  var provider = tls.provider.node.create();

  it('should create PRF', function() {
    var prf = new tls.utils.prf(provider.mac('sha256'))(
      new Buffer('1234'),
      new Buffer('label'),
      new Buffer('seed'));

    assert.equal(prf.read(256).length, 256);
  });
});
