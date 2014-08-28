var utils = exports;

var Buffer = require('buffer').Buffer;
var util = require('util');
var stream = require('stream');

utils.toPEM = function toPEM(type, data) {
  var text = data.toString('base64');
  var out = [ '-----BEGIN ' + type + '-----' ];
  for (var i = 0; i < text.length;)
    out.push(text.slice(i, i += 64));
  out.push('-----END ' + type + '-----');
  return out.join('\n');
};

utils.fromPEM = function fromPEM(data) {
  var text = data.toString().split(/(\r\n|\r|\n)+/g);
  text = text.filter(function(line) {
    return line.trim().length !== 0;
  });
  text = text.slice(1, -1).join('');
  return new Buffer(text.replace(/[^\w\d\+\/=]+/g, ''), 'base64');
};

utils.getLeaf = function getLeaf(crypto, certs) {
  // TODO(indunty): find leaf
  return certs[0];
};

utils.incSeq = function incSeq(buf) {
  for (var i = 7; i >= 0; i--) {
    if (buf[i] < 255) {
      buf[i]++;
      break;
    }
    buf[i] = 0;
  }
};

function NullCipher() {
}
utils.NullCipher = NullCipher;

NullCipher.prototype.write = function write(out, inp) {
  inp.copy(out);
};

function PRF(hmac, secret, label, seed) {
  this.hmac = hmac;

  // 32 bytes = 256 bits, we should not generate way too much entropy
  stream.Readable.call(this, {
    highWaterMark: 32
  });

  if (typeof label === 'string')
    label = new Buffer(label);

  this.secret = secret;
  this.label = label;
  this.seed = seed;
  this.pseed = Buffer.concat([ label, seed ], label.length + seed.length);

  // A(i) in RFC5246
  this.a = this.pseed;
}
util.inherits(PRF, stream.Readable);
exports.PRF = PRF;

exports.prf = function prf(hmac) {
  return function(secret, label, seed) {
    return new PRF(hmac, secret, label, seed);
  };
};

PRF.prototype.getA = function getA() {
  this.a = this.hmac(this.secret).update(this.a).digest('buffer');
  return this.a;
};

PRF.prototype._read = function read(size) {
  var off = 0;
  while (off < size) {
    var c = this.hmac(this.secret).update(this.getA())
                                  .update(this.pseed)
                                  .digest('buffer');
    this.push(c);
    off += c.length;
  }
};
