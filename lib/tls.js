var tls = exports;

tls.constants = require('./tls/constants');

tls.parsers = {};
tls.parsers.base = require('./tls/parsers/base');
tls.parsers.record = require('./tls/parsers/record');
