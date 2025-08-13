import struct
import time
import nacl.signing

import lib

class EdCert:
  def __init__(self, cert_type, key_type, key, exts, signed, signature):
    self.cert_type = cert_type
    self.key_type = key_type
    self.key = key
    self.exts = exts
    self.signed = signed
    self.signature = signature
  
  def __repr__(self):
    return f'EdCert({self.cert_type}, {self.key_type}, {self.key}, {self.exts}, {self.signed}, {self.signature})'
  
  def verify(self, key): # key is a nacl.signing.VerifyKey
    return key.verify(self.signed, self.signature)

def ed_key(key_data):
  return nacl.signing.VerifyKey(key_data, encoder = nacl.encoding.RawEncoder)

def decode_ed_certificate(cert_data):
  version,cert_type,expires,key_type,key,n = struct.unpack_from('>BBIB32sB', cert_data)
  assert version == 1, f'Ed certificate with unrecognized version {version}'
  assert expires > time.time() / 3600, f'expired Ed certificate' # `expires` is in hours since the epoch
  offset = 7 + 32 + 1
  exts = {}
  for i in range(n):
    ext_len,ext_type,ext_flags = struct.unpack_from('>HBB', cert_data, offset)
    offset += 4
    ext_data = lib.bytes_from(ext_len, cert_data, offset)
    offset += ext_len
    if ext_type == 4:
      assert ext_len == 32, f'Ed certificate extension of type 4 [signed-with-ed25519-key] has invalid length {ext_len}'
      ext_data = ed_key(ext_data)
    else:
      assert not (ext_flags & 1), f'Ed certificate extension necessary for validation with unrecognized type {ext_type}'
    assert ext_type not in exts, f'duplicate extension of type {ext_type} in Ed certificate' # do i need to check this?
    exts[ext_type] = ext_data
  signature = lib.bytes_from(64, cert_data, offset)
  signed = cert_data[:offset]
  offset += 64
  assert offset == len(cert_data), f'extra data after signature in Ed certificate' # is this something i need to check?
  return EdCert(cert_type, key_type, key, exts, signed, signature)