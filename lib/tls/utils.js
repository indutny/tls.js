var utils = exports;

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
