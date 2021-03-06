var constants = exports;
var Buffer = require('buffer').Buffer;

function reverseNum(obj) {
  var res = {};

  Object.keys(obj).forEach(function(key) {
    var val = this[key];
    res[val] = key | 0;
  }, obj);

  return res;
}

constants.prf = {
  master: new Buffer('master secret'),
  key: new Buffer('key expansion'),
  clientFin: new Buffer('client finished'),
  serverFin: new Buffer('server finished')
};

constants.masterLength = 48;

constants.recordType = {
  20: 'change_cipher_spec',
  21: 'alert',
  22: 'handshake',
  23: 'application_data',
  24: 'heartbeat'
};
constants.recordTypeByName = reverseNum(constants.recordType);

constants.alertLevel = {
  1: 'warning',
  2: 'fatal'
};
constants.alertLevelByName = reverseNum(constants.alertLevel);

constants.alertDescription = {
  0: 'close_notify',
  10: 'unexpected_message',
  20: 'bad_record_mac',
  21: 'decryption_failed_RESERVED',
  22: 'record_overflow',
  30: 'decompression_failure',
  40: 'handshake_failure',
  41: 'no_certificate_RESERVED',
  42: 'bad_certificate',
  43: 'unsupported_certificate',
  44: 'certificate_revoked',
  45: 'certificate_expired',
  46: 'certificate_unknown',
  47: 'illegal_parameter',
  48: 'unknown_ca',
  49: 'access_denied',
  50: 'decode_error',
  51: 'decrypt_error',
  52: 'export_restriction_RESERVED',
  70: 'protocol_version',
  71: 'insufficient_security',
  80: 'internal_error',
  90: 'user_canceled',
  100: 'no_renegotiation',
  110: 'unsupported_extension'
};
constants.alertDescriptionByName = reverseNum(constants.alertDescription);

constants.handshakeType = {
  0: 'hello_request',
  1: 'client_hello',
  2: 'server_hello',
  4: 'session_ticket',
  11: 'certificate',
  12: 'server_key_exchange',
  13: 'certificate_request',
  14: 'server_hello_done',
  15: 'certificate_verify',
  16: 'client_key_exchange',
  20: 'finished',
  67: 'next_protocol'
};
constants.handshakeTypeByName = reverseNum(constants.handshakeType);

constants.extensionType = {
  0: 'server_name',
  1: 'max_fragment_length',
  2: 'client_certificate_url',
  3: 'trusted_ca_keys',
  4: 'trusted_hmac',
  5: 'status_request',
  6: 'user_mapping',
  7: 'client_authz',
  8: 'server_authz',
  9: 'cert_type',
  10: 'elliptic_curves',
  11: 'ec_point_formats',
  12: 'srp',
  13: 'signature_algorithms',
  14: 'use_srtp',
  15: 'heartbeat',
  16: 'application_level_protocol_negotiation',
  17: 'status_request_v2',
  18: 'signed_certificate_timestamp',
  35: 'session_ticket_tls',
  13172: 'next_protocol_negotiation',
  65281: 'renegotiation_info'
};
constants.extensionTypeByName = reverseNum(constants.extensionType);

constants.hashAlgorithm = {
  0: 'none',
  1: 'md5',
  2: 'sha1',
  3: 'sha224',
  4: 'sha256',
  5: 'sha384',
  6: 'sha512'
};
constants.hashAlgorithmByName = reverseNum(constants.hashAlgorithm);

constants.signatureAlgorithm = {
  0: 'anonymous',
  1: 'rsa',
  2: 'dsa',
  3: 'ecdsa'
};
constants.signatureAlgorithmByName = reverseNum(constants.signatureAlgorithm);

constants.heartbeatType = {
  1: 'heartbeat_request',
  2: 'heartbeat_response'
};
constants.heartbeatTypeByName = reverseNum(constants.heartbeatType);

constants.heartbeatMode = {
  1: 'peer_allowed_to_send',
  2: 'peer_not_allowed_to_send'
};
constants.heartbeatModeByName = reverseNum(constants.heartbeatMode);

constants.clientCertType = {
  1: 'rsa_sign',
  2: 'dss_sign',
  3: 'rsa_fixed_dh',
  4: 'dss_fixed_dh',
  5: 'rsa_ephemeral_dh_RESERVED',
  6: 'dss_ephemeral_dh_RESERVED',
  20: 'fortezza_dms_RESERVED'
};

constants.clientCertTypeByName = reverseNum(constants.clientCertType);

constants.compressionMethod = {
  0:  'null',
  1:  'deflate'
};

constants.compressionMethodByName = reverseNum(constants.compressionMethod);

constants.curveType = {
  1: 'explicit_prime',
  2: 'explicit_char2',
  3: 'named_curve'
};

constants.curveTypeByName = reverseNum(constants.curveType);

constants.namedCurve = {
  1: 'sect163k1',
  2: 'sect163r1',
  3: 'sect163r2',
  4: 'sect193r1',
  5: 'sect193r2',
  6: 'sect233k1',
  7: 'sect233r1',
  8: 'sect239k1',
  9: 'sect283k1',
  10: 'sect283r1',
  11: 'sect409k1',
  12: 'sect409r1',
  13: 'sect571k1',
  14: 'sect571r1',
  15: 'secp160k1',
  16: 'secp160r1',
  17: 'secp160r2',
  18: 'secp192k1',
  19: 'secp192r1',
  20: 'secp224k1',
  21: 'secp224r1',
  22: 'secp256k1',
  23: 'secp256r1',
  24: 'secp384r1',
  25: 'secp521r1'
};

constants.namedCurveByName = reverseNum(constants.namedCurve);

constants.cipherSuite = {
  0x0000: 'TLS_NULL_WITH_NULL_NULL',
  0x0001: 'TLS_RSA_WITH_NULL_MD5',
  0x0002: 'TLS_RSA_WITH_NULL_SHA',
  0x0003: 'TLS_RSA_EXPORT_WITH_RC4_40_MD5',
  0x0004: 'TLS_RSA_WITH_RC4_128_MD5',
  0x0005: 'TLS_RSA_WITH_RC4_128_SHA',
  0x0006: 'TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5',
  0x0007: 'TLS_RSA_WITH_IDEA_CBC_SHA',
  0x0008: 'TLS_RSA_EXPORT_WITH_DES40_CBC_SHA',
  0x0009: 'TLS_RSA_WITH_DES_CBC_SHA',
  0x000A: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
  0x000B: 'TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA',
  0x000C: 'TLS_DH_DSS_WITH_DES_CBC_SHA',
  0x000D: 'TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA',
  0x000E: 'TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA',
  0x000F: 'TLS_DH_RSA_WITH_DES_CBC_SHA',
  0x0010: 'TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA',
  0x0011: 'TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA',
  0x0012: 'TLS_DHE_DSS_WITH_DES_CBC_SHA',
  0x0013: 'TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA',
  0x0014: 'TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA',
  0x0015: 'TLS_DHE_RSA_WITH_DES_CBC_SHA',
  0x0016: 'TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA',
  0x0017: 'TLS_DH_anon_EXPORT_WITH_RC4_40_MD5',
  0x0018: 'TLS_DH_anon_WITH_RC4_128_MD5',
  0x0019: 'TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA',
  0x001A: 'TLS_DH_anon_WITH_DES_CBC_SHA',
  0x001B: 'TLS_DH_anon_WITH_3DES_EDE_CBC_SHA',
  0x001E: 'TLS_KRB5_WITH_DES_CBC_SHA',
  0x001F: 'TLS_KRB5_WITH_3DES_EDE_CBC_SHA',
  0x0020: 'TLS_KRB5_WITH_RC4_128_SHA',
  0x0021: 'TLS_KRB5_WITH_IDEA_CBC_SHA',
  0x0022: 'TLS_KRB5_WITH_DES_CBC_MD5',
  0x0023: 'TLS_KRB5_WITH_3DES_EDE_CBC_MD5',
  0x0024: 'TLS_KRB5_WITH_RC4_128_MD5',
  0x0025: 'TLS_KRB5_WITH_IDEA_CBC_MD5',
  0x0026: 'TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA',
  0x0027: 'TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA',
  0x0028: 'TLS_KRB5_EXPORT_WITH_RC4_40_SHA',
  0x0029: 'TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5',
  0x002A: 'TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5',
  0x002B: 'TLS_KRB5_EXPORT_WITH_RC4_40_MD5',
  0x002C: 'TLS_PSK_WITH_NULL_SHA',
  0x002D: 'TLS_DHE_PSK_WITH_NULL_SHA',
  0x002E: 'TLS_RSA_PSK_WITH_NULL_SHA',
  0x002F: 'TLS_RSA_WITH_AES_128_CBC_SHA',
  0x0030: 'TLS_DH_DSS_WITH_AES_128_CBC_SHA',
  0x0031: 'TLS_DH_RSA_WITH_AES_128_CBC_SHA',
  0x0032: 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA',
  0x0033: 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA',
  0x0034: 'TLS_DH_anon_WITH_AES_128_CBC_SHA',
  0x0035: 'TLS_RSA_WITH_AES_256_CBC_SHA',
  0x0036: 'TLS_DH_DSS_WITH_AES_256_CBC_SHA',
  0x0037: 'TLS_DH_RSA_WITH_AES_256_CBC_SHA',
  0x0038: 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA',
  0x0039: 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA',
  0x003A: 'TLS_DH_anon_WITH_AES_256_CBC_SHA',
  0x003B: 'TLS_RSA_WITH_NULL_SHA256',
  0x003C: 'TLS_RSA_WITH_AES_128_CBC_SHA256',
  0x003D: 'TLS_RSA_WITH_AES_256_CBC_SHA256',
  0x003E: 'TLS_DH_DSS_WITH_AES_128_CBC_SHA256',
  0x003F: 'TLS_DH_RSA_WITH_AES_128_CBC_SHA256',
  0x0040: 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA256',
  0x0041: 'TLS_RSA_WITH_CAMELLIA_128_CBC_SHA',
  0x0042: 'TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA',
  0x0043: 'TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA',
  0x0044: 'TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA',
  0x0045: 'TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA',
  0x0046: 'TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA',
  0x0067: 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA256',
  0x0068: 'TLS_DH_DSS_WITH_AES_256_CBC_SHA256',
  0x0069: 'TLS_DH_RSA_WITH_AES_256_CBC_SHA256',
  0x006A: 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA256',
  0x006B: 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA256',
  0x006C: 'TLS_DH_anon_WITH_AES_128_CBC_SHA256',
  0x006D: 'TLS_DH_anon_WITH_AES_256_CBC_SHA256',
  0x0084: 'TLS_RSA_WITH_CAMELLIA_256_CBC_SHA',
  0x0085: 'TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA',
  0x0086: 'TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA',
  0x0087: 'TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA',
  0x0088: 'TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA',
  0x0089: 'TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA',
  0x008A: 'TLS_PSK_WITH_RC4_128_SHA',
  0x008B: 'TLS_PSK_WITH_3DES_EDE_CBC_SHA',
  0x008C: 'TLS_PSK_WITH_AES_128_CBC_SHA',
  0x008D: 'TLS_PSK_WITH_AES_256_CBC_SHA',
  0x008E: 'TLS_DHE_PSK_WITH_RC4_128_SHA',
  0x008F: 'TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA',
  0x0090: 'TLS_DHE_PSK_WITH_AES_128_CBC_SHA',
  0x0091: 'TLS_DHE_PSK_WITH_AES_256_CBC_SHA',
  0x0092: 'TLS_RSA_PSK_WITH_RC4_128_SHA',
  0x0093: 'TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA',
  0x0094: 'TLS_RSA_PSK_WITH_AES_128_CBC_SHA',
  0x0095: 'TLS_RSA_PSK_WITH_AES_256_CBC_SHA',
  0x0096: 'TLS_RSA_WITH_SEED_CBC_SHA',
  0x0097: 'TLS_DH_DSS_WITH_SEED_CBC_SHA',
  0x0098: 'TLS_DH_RSA_WITH_SEED_CBC_SHA',
  0x0099: 'TLS_DHE_DSS_WITH_SEED_CBC_SHA',
  0x009A: 'TLS_DHE_RSA_WITH_SEED_CBC_SHA',
  0x009B: 'TLS_DH_anon_WITH_SEED_CBC_SHA',
  0x009C: 'TLS_RSA_WITH_AES_128_GCM_SHA256',
  0x009D: 'TLS_RSA_WITH_AES_256_GCM_SHA384',
  0x009E: 'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256',
  0x009F: 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384',
  0x00A0: 'TLS_DH_RSA_WITH_AES_128_GCM_SHA256',
  0x00A1: 'TLS_DH_RSA_WITH_AES_256_GCM_SHA384',
  0x00A2: 'TLS_DHE_DSS_WITH_AES_128_GCM_SHA256',
  0x00A3: 'TLS_DHE_DSS_WITH_AES_256_GCM_SHA384',
  0x00A4: 'TLS_DH_DSS_WITH_AES_128_GCM_SHA256',
  0x00A5: 'TLS_DH_DSS_WITH_AES_256_GCM_SHA384',
  0x00A6: 'TLS_DH_anon_WITH_AES_128_GCM_SHA256',
  0x00A7: 'TLS_DH_anon_WITH_AES_256_GCM_SHA384',
  0x00A8: 'TLS_PSK_WITH_AES_128_GCM_SHA256',
  0x00A9: 'TLS_PSK_WITH_AES_256_GCM_SHA384',
  0x00AA: 'TLS_DHE_PSK_WITH_AES_128_GCM_SHA256',
  0x00AB: 'TLS_DHE_PSK_WITH_AES_256_GCM_SHA384',
  0x00AC: 'TLS_RSA_PSK_WITH_AES_128_GCM_SHA256',
  0x00AD: 'TLS_RSA_PSK_WITH_AES_256_GCM_SHA384',
  0x00AE: 'TLS_PSK_WITH_AES_128_CBC_SHA256',
  0x00AF: 'TLS_PSK_WITH_AES_256_CBC_SHA384',
  0x00B0: 'TLS_PSK_WITH_NULL_SHA256',
  0x00B1: 'TLS_PSK_WITH_NULL_SHA384',
  0x00B2: 'TLS_DHE_PSK_WITH_AES_128_CBC_SHA256',
  0x00B3: 'TLS_DHE_PSK_WITH_AES_256_CBC_SHA384',
  0x00B4: 'TLS_DHE_PSK_WITH_NULL_SHA256',
  0x00B5: 'TLS_DHE_PSK_WITH_NULL_SHA384',
  0x00B6: 'TLS_RSA_PSK_WITH_AES_128_CBC_SHA256',
  0x00B7: 'TLS_RSA_PSK_WITH_AES_256_CBC_SHA384',
  0x00B8: 'TLS_RSA_PSK_WITH_NULL_SHA256',
  0x00B9: 'TLS_RSA_PSK_WITH_NULL_SHA384',
  0x00BA: 'TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256',
  0x00BB: 'TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256',
  0x00BC: 'TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256',
  0x00BD: 'TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256',
  0x00BE: 'TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256',
  0x00BF: 'TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256',
  0x00C0: 'TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256',
  0x00C1: 'TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256',
  0x00C2: 'TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256',
  0x00C3: 'TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256',
  0x00C4: 'TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256',
  0x00C5: 'TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256',
  0xC002: 'TLS_ECDH_ECDSA_WITH_RC4_128_SHA',
  0xC003: 'TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA',
  0xC004: 'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA',
  0xC005: 'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA',
  0xC006: 'TLS_ECDHE_ECDSA_WITH_NULL_SHA',
  0xC007: 'TLS_ECDHE_ECDSA_WITH_RC4_128_SHA',
  0xC008: 'TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA',
  0xC009: 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA',
  0xC00A: 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA',
  0xC00B: 'TLS_ECDH_RSA_WITH_NULL_SHA',
  0xC00C: 'TLS_ECDH_RSA_WITH_RC4_128_SHA',
  0xC00D: 'TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA',
  0xC00E: 'TLS_ECDH_RSA_WITH_AES_128_CBC_SHA',
  0xC00F: 'TLS_ECDH_RSA_WITH_AES_256_CBC_SHA',
  0xC010: 'TLS_ECDHE_RSA_WITH_NULL_SHA',
  0xC011: 'TLS_ECDHE_RSA_WITH_RC4_128_SHA',
  0xC012: 'TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA',
  0xC013: 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
  0xC014: 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
  0xC015: 'TLS_ECDH_anon_WITH_NULL_SHA',
  0xC016: 'TLS_ECDH_anon_WITH_RC4_128_SHA',
  0xC017: 'TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA',
  0xC018: 'TLS_ECDH_anon_WITH_AES_128_CBC_SHA',
  0xC019: 'TLS_ECDH_anon_WITH_AES_256_CBC_SHA',
  0xC01A: 'TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA',
  0xC01B: 'TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA',
  0xC01C: 'TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA',
  0xC01D: 'TLS_SRP_SHA_WITH_AES_128_CBC_SHA',
  0xC01E: 'TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA',
  0xC01F: 'TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA',
  0xC020: 'TLS_SRP_SHA_WITH_AES_256_CBC_SHA',
  0xC021: 'TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA',
  0xC022: 'TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA',
  0xC023: 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256',
  0xC024: 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384',
  0xC025: 'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256',
  0xC026: 'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384',
  0xC027: 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',
  0xC028: 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',
  0xC029: 'TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256',
  0xC02A: 'TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384',
  0xC02B: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
  0xC02C: 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
  0xC02D: 'TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256',
  0xC02E: 'TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384',
  0xC02F: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
  0xC030: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
  0xC031: 'TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256',
  0xC032: 'TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384',
  0xC033: 'TLS_ECDHE_PSK_WITH_RC4_128_SHA',
  0xC034: 'TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA',
  0xC035: 'TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA',
  0xC036: 'TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA',
  0xC037: 'TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256',
  0xC038: 'TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384',
  0xC039: 'TLS_ECDHE_PSK_WITH_NULL_SHA',
  0xC03A: 'TLS_ECDHE_PSK_WITH_NULL_SHA256',
  0xC03B: 'TLS_ECDHE_PSK_WITH_NULL_SHA384',
  0xC03C: 'TLS_RSA_WITH_ARIA_128_CBC_SHA256',
  0xC03D: 'TLS_RSA_WITH_ARIA_256_CBC_SHA384',
  0xC03E: 'TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256',
  0xC03F: 'TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384',
  0xC040: 'TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256',
  0xC041: 'TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384',
  0xC042: 'TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256',
  0xC043: 'TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384',
  0xC044: 'TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256',
  0xC045: 'TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384',
  0xC046: 'TLS_DH_anon_WITH_ARIA_128_CBC_SHA256',
  0xC047: 'TLS_DH_anon_WITH_ARIA_256_CBC_SHA384',
  0xC048: 'TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256',
  0xC049: 'TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384',
  0xC04A: 'TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256',
  0xC04B: 'TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384',
  0xC04C: 'TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256',
  0xC04D: 'TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384',
  0xC04E: 'TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256',
  0xC04F: 'TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384',
  0xC050: 'TLS_RSA_WITH_ARIA_128_GCM_SHA256',
  0xC051: 'TLS_RSA_WITH_ARIA_256_GCM_SHA384',
  0xC052: 'TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256',
  0xC053: 'TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384',
  0xC054: 'TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256',
  0xC055: 'TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384',
  0xC056: 'TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256',
  0xC057: 'TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384',
  0xC058: 'TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256',
  0xC059: 'TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384',
  0xC05A: 'TLS_DH_anon_WITH_ARIA_128_GCM_SHA256',
  0xC05B: 'TLS_DH_anon_WITH_ARIA_256_GCM_SHA384',
  0xC05C: 'TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256',
  0xC05D: 'TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384',
  0xC05E: 'TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256',
  0xC05F: 'TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384',
  0xC060: 'TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256',
  0xC061: 'TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384',
  0xC062: 'TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256',
  0xC063: 'TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384',
  0xC064: 'TLS_PSK_WITH_ARIA_128_CBC_SHA256',
  0xC065: 'TLS_PSK_WITH_ARIA_256_CBC_SHA384',
  0xC066: 'TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256',
  0xC067: 'TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384',
  0xC068: 'TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256',
  0xC069: 'TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384',
  0xC06A: 'TLS_PSK_WITH_ARIA_128_GCM_SHA256',
  0xC06B: 'TLS_PSK_WITH_ARIA_256_GCM_SHA384',
  0xC06C: 'TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256',
  0xC06D: 'TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384',
  0xC06E: 'TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256',
  0xC06F: 'TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384',
  0xC070: 'TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256',
  0xC071: 'TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384',
  0xC072: 'TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256',
  0xC073: 'TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384',
  0xC074: 'TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256',
  0xC075: 'TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384',
  0xC076: 'TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256',
  0xC077: 'TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384',
  0xC078: 'TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256',
  0xC079: 'TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384',
  0xC07A: 'TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256',
  0xC07B: 'TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384',
  0xC07C: 'TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256',
  0xC07D: 'TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384',
  0xC07E: 'TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256',
  0xC07F: 'TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384',
  0xC080: 'TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256',
  0xC081: 'TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384',
  0xC082: 'TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256',
  0xC083: 'TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384',
  0xC084: 'TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256',
  0xC085: 'TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384',
  0xC086: 'TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256',
  0xC087: 'TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384',
  0xC088: 'TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256',
  0xC089: 'TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384',
  0xC08A: 'TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256',
  0xC08B: 'TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384',
  0xC08C: 'TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256',
  0xC08D: 'TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384',
  0xC08E: 'TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256',
  0xC08F: 'TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384',
  0xC090: 'TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256',
  0xC091: 'TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384',
  0xC092: 'TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256',
  0xC093: 'TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384',
  0xC094: 'TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256',
  0xC095: 'TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384',
  0xC096: 'TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256',
  0xC097: 'TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384',
  0xC098: 'TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256',
  0xC099: 'TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384',
  0xC09A: 'TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256',
  0xC09B: 'TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384'
};

constants.cipherSuiteByName = {};
Object.keys(constants.cipherSuite).forEach(function(id) {
  var name = constants.cipherSuite[id],
      numId = parseInt(id, 10);
  constants.cipherSuiteByName[name] = numId;
});

var cipherRe = new RegExp(
  '^TLS' +
      '(?:_(DH|DHE|ECDH|ECDHE))?' + // DH
      '_(.*)' + // Auth
      '_WITH' +
      '_(.*)' + // Bulk
      '_([^_]*)$', // Mac
  'i'
);

constants.cipherInfoByName = {};
Object.keys(constants.cipherSuiteByName).forEach(function(name) {
  // Determine bulk cipher
  var match = name.toLowerCase().match(cipherRe);
  if (!match)
    throw new Error('failed to match cipher name: ' + name);

  var dh = match[1];
  var auth = match[2];
  var bulk = {
    name: match[3],
    gcm: /gcm/.test(match[3]),
    cbc: /cbc/.test(match[3])
  };

  bulk.size = bulk.name.match(/^.+?(\d{2,})/);
  if (bulk.size)
    bulk.size = bulk.size[1] | 0;
  else
    bulk.size = 0;

  // Determine bulk size for known bulk ciphers
  if (bulk.size === 0 && bulk.name !== 'null') {
    bulk.size = /^(3?des|idea)/.test(bulk.name) ? 64 :
                /^seed/.test(bulk.name) ? 128 :
                0;
  }

  var mac = match[4];
  var macSize = mac.match(/\d+/);
  if (macSize)
    macSize = macSize[0] | 0;
  else
    macSize = 0;

  // NOTE: Other MACs have bitsize incorporated in the name
  if (mac === 'sha') {
    mac = 'sha1';
    macSize = 160;
  } else if (mac === 'md5') {
    macSize = 128;
  }

  var keySize = bulk.size;
  var ivSize;

  if (/aes/.test(bulk.name)) {
    bulk.size = 128;
    ivSize = bulk.size;
  } else if (/rc4/.test(bulk.name)) {
    ivSize = 0;
  } else if (/idea/.test(bulk.name)) {
    keySize = 128;
    ivSize = bulk.size;
  } else {
    // TODO(indutny): is it true for others?
    ivSize = keySize;
  }

  if (/3des/.test(bulk.name)) {
    keySize = 3 * 64;

    // Translate OpenSSL readable form
    bulk.name = bulk.name.replace(/3des/g, 'des').replace(/ede/g, 'ede3');
  } else if (/rc4_128/.test(bulk.name)) {
    bulk.name = bulk.name.replace(/rc4_128/g, 'rc4');
  }

  var minVersion = 0x0300;
  if (mac === 'sha256' || mac === 'sha384')
    minVersion = 0x0303;

  constants.cipherInfoByName[name] = {
    type: bulk.gcm ? 'aead' :
          /rc4|camellia|null/.test(bulk.name) ? 'stream' : 'block',
    dh: match[1] || null,
    auth: auth.replace(/_+/g, '-'),
    bulk: {
      name: bulk.name.replace(/_+/g, '-'),
      cbc: bulk.cbc,
      gcm: bulk.gcm,
      keySize: keySize,
      size: bulk.size,
      ivSize: ivSize
    },
    version: {
      min: minVersion
    },
    mac: mac,
    macSize: macSize,

    // TODO(indutny): Find section in spec that requires this
    prf: mac === 'sha384' ? mac : 'sha256',

    // TODO(indutny): Is it true for every supported cipher?
    verifyLength: 12
  };
});
