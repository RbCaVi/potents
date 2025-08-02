# tor <3

# notes
# KP / KS - public and private (secret) keys for asymmetric cipher
# K - key for a symmetric cipher
# N - nonce - random or hashed from other inputs
# H(m) - cryptographic hash of m
# base32 has no padding
# integers are big endian - struct.pack('>*', *)

import ssl
import time
import socket
import struct
import nacl.signing
import hashlib

KEY_LEN = 16 # size of stream cipher key in bytes
KP_ENC_LEN = 128 # length of public key encrypted message in bytes
KP_PAD_LEN = 42 # bytes of padding added before encryption - you can only encrypt `KP_ENC_LEN - KP_PAD_LEN` bytes at a time

DH_LEN = 128 # size of a member of the diffie hellman group - in bytes
DH_SEC_LEN = 40 # size of a dh private key in bytes

HASH_LEN = 20 # length of the hash output in bytes

FIXED_PAYLOAD_LEN = 509 # longest payload in bytes

def init_stream_cipher(): # 128 bit AES - stream mode - IV all 0
  raise NotImplementedError

def pk_encrypt(data, key): # RSA with 128 bit keys and exponent 65537 - oaep mgf1 padding with sha1 digest - label unset - ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-1/pkcs-1v2-1.pdf
  raise NotImplementedError

# curve25519 group and ed25519 signature

# diffie hellman generator is 2
# this is the modulus p (from rfc2409 section 6.2)
# you should use a 320 bit dh key - never reused
'''
FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74
020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437
4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED
EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF
'''

# hash functions
# sha1 sha256 sha3-256
# sha1 is deprecated and should not be used

def sha1(data):
  print("SHA1 is deprecated :((((((((((")
  return hashlib.sha1(data).digest()

def sha256(data):
  return hashlib.sha256(data).digest()

def sha3_256(data):
  return hashlib.sha3_256(data).digest()

def hash_pk(pk): # sha1 of der encoding of asn1 rsa key from pkcs1
  raise NotImplementedError

# skipping the 1.1 keys and names section for now

# cell commands
# fixed length
PADDING = 0 # Padding
CREATE = 1 # Create a circuit
CREATED = 2 # Acknowledge create
RELAY = 3 # End-to-end data
DESTROY = 4 # Stop using a circuit
CREATE_FAST = 5 # Create a circuit, no KP
CREATED_FAST = 6 # Circuit created, no KP
NETINFO = 8 # Time and address info
RELAY_EARLY = 9 # End-to-end data; limited
CREATE2 = 10 # Extended CREATE cell
CREATED2 = 11 # Extended CREATED cell
PADDING_NEGOTIATE = 12 # Padding negotiation
fixed_length_commands = [PADDING, CREATE, CREATED, RELAY, DESTROY, CREATE_FAST, CREATED_FAST, NETINFO, RELAY_EARLY, CREATE2, CREATED2, PADDING_NEGOTIATE]

# variable length
VERSIONS = 7 # Negotiate proto version
VPADDING = 128 # Variable-length padding
CERTS = 129 # Certificates
AUTH_CHALLENGE = 130 # Challenge value
AUTHENTICATE = 131 # Client authentication
variable_length_commands = [VERSIONS, VPADDING, CERTS, AUTH_CHALLENGE, AUTHENTICATE]

# note: i didn't include AUTHORIZE because it says not used

def pack_fixed_length_cell(circid, command, payload, version):
  assert len(payload) == FIXED_PAYLOAD_LEN, f'payload of wrong length: {len(payload)}'
  if version < 4:
    return struct.pack('>HB509s', circid, command, payload) # circuit id is 2 bytes for version less than 4
  else:
    return struct.pack('>IB509s', circid, command, payload) # and 4 bytes otherwise

def pack_variable_length_cell(circid, command, payload, version):
  if version < 4:
    return struct.pack('>HBH', circid, command, len(payload)) + payload # circuit id is 2 bytes for version less than 4
  else:
    return struct.pack('>IBH', circid, command, len(payload)) + payload # and 4 bytes otherwise

def pack_cell(circid, command, payload, version):
  if command in fixed_length_commands:
    return pack_fixed_length_cell(circid, command, payload, version)
  elif command in variable_length_commands:
    return pack_variable_length_cell(circid, command, payload, version)
  else:
    raise NotImplementedError

class Cell:
  def __init__(self, circid, command, payload):
    self.circid = circid
    self.command = command
    self.payload = payload
  
  def pack(self, version):
    return pack_cell(self.circid, self.command, self.payload, version)
  
  def __repr__(self):
    return f'Cell({self.circid}, {self.command}, {self.payload})'

def get_context():
  context = ssl.create_default_context()
  context.check_hostname = False
  context.verify_mode = ssl.VerifyMode.CERT_NONE
  return context

torcontext = get_context() # doesn't need to be customizable right?

# get `size` bytes starting from `offset`
def bytes_from(size, data, offset): # argument order to match struct.unpack_from()
  assert offset + size <= len(data), 'not enough bytes to return from bytes_from()'
  return data[offset:offset + size]

def unpack_cell(data, version):
  if version < 4:
    if len(data) < 2 + 1: # circuit id + command - i'm going to struct.unpack() it
      return None, data
    circuitid,command = struct.unpack_from('>HB', data)
    offset = 2 + 1
  else:
    if len(data) < 4 + 1: # circuit id + command - i'm going to struct.unpack() it
      return None, data
    circuitid,command = struct.unpack_from('>IB', data)
    offset = 4 + 1
  if command in fixed_length_commands:
    payload = bytes_from(FIXED_PAYLOAD_LEN, data, offset)
    offset += FIXED_PAYLOAD_LEN
    return Cell(circuitid, command, payload), data[offset:]
  elif command in variable_length_commands:
    payload_len, = struct.unpack_from('>H', data, offset)
    offset += 2
    payload = bytes_from(payload_len, data, offset)
    offset += payload_len
    return Cell(circuitid, command, payload), data[offset:]
  else:
    raise NotImplementedError

# read and write cells easily
# plagiarized from myself <3333
class CellSocket:
  def __init__(self, conn):
    self.conn = conn
    self.buffer = b''
    self.version = 0

  def recv(self):
    while True:
      cell,self.buffer = unpack_cell(self.buffer, self.version)
      if cell is not None:
        if cell.command != PADDING:
          return cell
        else:
          print("padding", cell)
      while True: # nested infinite while loop >:)
        # basically wait until a chunk has been recieved
        chunk = self.conn.recv(2048)
        if chunk != b'':
          self.buffer += chunk
          break
        else:
          print(self.buffer)
          time.sleep(1)
          print("Not enough data for a complete cell, waiting...")
          # uhh timeout maybe???

  def send(self, cell):
    self.conn.send(cell.pack(self.version))
  
  def close(self):
    self.conn.close()

def encode_versions_cell(versions):
  return Cell(0, VERSIONS, b''.join(struct.pack('>H', v) for v in versions))

def decode_versions_cell(cell):
  assert cell.command == VERSIONS, 'attempted to decode non-VERSIONS cell using decode_versions_cell()'
  return {v for v, in struct.iter_unpack('>H', cell.payload)}

# certificate types
#TLS_LINK_X509 = 1 # obsolete
#RSA_ID_X509 = 2 # obsolete
#LINK_AUTH_X509 = 3 # obsolete
IDENTITY_V_SIGNING = 4
SIGNING_V_TLS_CERT = 5
#SIGNING_V_LINK_AUTH = 6 # not used right now
#RSA_ID_V_IDENTITY = 7 # not used right now
#BLINDED_ID_V_SIGNING = 8 # not used right now
#HS_IP_V_SIGNING = 9 # not used right now
#NTOR_CC_IDENTITY = 10 # not used right now
#HS_IP_CC_SIGNING = 11 # not used right now
#FAMILY_V_IDENTITY = 12 # not used right now

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
    ext_data = bytes_from(ext_len, cert_data, offset)
    offset += ext_len
    if ext_type == 4:
      assert ext_len == 32, f'Ed certificate extension of type 4 [signed-with-ed25519-key] has invalid length {ext_len}'
      ext_data = ed_key(ext_data)
    else:
      assert not (ext_flags & 1), f'Ed certificate extension necessary for validation with unrecognized type {ext_type}'
    assert ext_type not in exts, f'duplicate extension of type {ext_type} in Ed certificate' # do i need to check this?
    exts[ext_type] = ext_data
  signature = bytes_from(64, cert_data, offset)
  signed = cert_data[:offset]
  offset += 64
  assert offset == len(cert_data), f'extra data after signature in Ed certificate' # is this something i need to check?
  return EdCert(cert_type, key_type, key, exts, signed, signature)

def decode_certs_cell(cell):
  assert cell.command == CERTS, 'attempted to decode non-CERTS cell using decode_certs_cell()'
  n, = struct.unpack_from('>B', cell.payload) # number of certificates
  offset = 1
  certs = {}
  for i in range(n):
    cert_type,cert_len = struct.unpack_from('>BH', cell.payload, offset)
    offset += 3
    cert_data = bytes_from(cert_len, cell.payload, offset)
    offset += cert_len
    if cert_type == IDENTITY_V_SIGNING:
      cert_data = decode_ed_certificate(cert_data)
      assert cert_data.cert_type == cert_type, f'mismatched certificate type [{cert_data.cert_type}] inside Ed certificate of type 4 in CERTS_CELL'
    if cert_type == SIGNING_V_TLS_CERT:
      cert_data = decode_ed_certificate(cert_data)
      assert cert_data.cert_type == cert_type, f'mismatched certificate type [{cert_data.cert_type}] inside Ed certificate of type 5 in CERTS_CELL'
    # i'm going to ignore all the other certificates anyway so i don't have to process them
    assert cert_type not in certs, f'duplicate certificate of type {cert_type} in CERTS cell'
    certs[cert_type] = cert_data
  return certs

# connects to the relay without authenticating
# takes a (ip, port) pair
def connect(relay):
  s = torcontext.wrap_socket(socket.socket(socket.AF_INET))
  s.connect(relay)
  conn = CellSocket(s)
  
  lversions = {4}
  conn.send(encode_versions_cell(lversions))
  rversions = decode_versions_cell(conn.recv())
  conn.version = max(lversions & rversions)
  
  certs = decode_certs_cell(conn.recv())
  
  assert certs[IDENTITY_V_SIGNING].key_type == 1, f'incorrect key type {certs[IDENTITY_V_SIGNING].key_type} for IDENTITY_V_SIGNING certificate'
  KP_relayid_ed = certs[IDENTITY_V_SIGNING].exts[4]
  assert certs[IDENTITY_V_SIGNING].verify(KP_relayid_ed)
  KP_relaysign_ed = ed_key(certs[IDENTITY_V_SIGNING].key)
  
  assert certs[SIGNING_V_TLS_CERT].key_type in [1, 3], f'incorrect key type {certs[IDENTITY_V_SIGNING].key_type} for SIGNING_V_TLS_CERT certificate' # technically it should be 3, but old tor put 1 for no reason so
  assert certs[SIGNING_V_TLS_CERT].verify(KP_relaysign_ed)
  servercert = s.getpeercert(binary_form = True)
  assert certs[SIGNING_V_TLS_CERT].key == sha256(servercert)
  
  challenge = conn.recv()
  assert challenge.command == AUTH_CHALLENGE
  
  return conn, KP_relayid_ed, KP_relaysign_ed # the certificates aren't important right?

auth_dirs = [ # the contents of https://gitlab.torproject.org/tpo/core/tor/-/blob/main/src/app/config/auth_dirs.inc
"moria1 orport=9201 "
  "v3ident=F533C81CEF0BC0267857C99B2F471ADF249FA232 "
  "128.31.0.39:9231 1A25C6358DB91342AA51720A5038B72742732498",
"tor26 orport=443 "
  "v3ident=2F3DF9CA0E5D36F2685A2DA67184EB8DCB8CBA8C "
  "ipv6=[2a02:16a8:662:2203::1]:443 "
  "217.196.147.77:80 FAA4 BCA4 A6AC 0FB4 CA2F 8AD5 A11D 9E12 2BA8 94F6",
"dizum orport=443 "
  "v3ident=E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58 "
  "45.66.35.11:80 7EA6 EAD6 FD83 083C 538F 4403 8BBF A077 587D D755",
"Serge orport=9001 bridge "
  "66.111.2.131:9030 BA44 A889 E64B 93FA A2B1 14E0 2C2A 279A 8555 C533",
"gabelmoo orport=443 "
  "v3ident=ED03BB616EB2F60BEC80151114BB25CEF515B226 "
  "ipv6=[2001:638:a000:4140::ffff:189]:443 "
  "131.188.40.189:80 F204 4413 DAC2 E02E 3D6B CF47 35A1 9BCA 1DE9 7281",
"dannenberg orport=443 "
  "v3ident=0232AF901C31A04EE9848595AF9BB7620D4C5B2E "
  "ipv6=[2001:678:558:1000::244]:443 "
  "193.23.244.244:80 7BE6 83E6 5D48 1413 21C5 ED92 F075 C553 64AC 7123",
"maatuska orport=80 "
  "v3ident=49015F787433103580E3B66A1707A00E60F2D15B "
  "ipv6=[2001:67c:289c::9]:80 "
  "171.25.193.9:443 BD6A 8292 55CB 08E6 6FBE 7D37 4836 3586 E46B 3810",
"longclaw orport=443 "
  "v3ident=23D15D965BC35114467363C165C4F724B64B4F66 "
  "199.58.81.140:80 74A9 1064 6BCE EFBC D2E8 74FC 1DC9 9743 0F96 8145",
"bastet orport=443 "
  "v3ident=27102BC123E7AF1D4741AE047E160C91ADC76B21 "
  "ipv6=[2620:13:4000:6000::1000:118]:443 "
  "204.13.164.118:80 24E2 F139 121D 4394 C54B 5BCC 368B 3B41 1857 C413",
"faravahar orport=443 "
  "v3ident=70849B868D606BAECFB6128C5E3D782029AA394F "
  "216.218.219.41:80 E3E4 2D35 F801 C9D5 AB23 584E 0025 D56F E2B3 3396",
]

# from https://gitlab.torproject.org/tpo/core/tor/-/blob/main/src/app/config/config.c#L5593
def parse_auth_dir(auth_dir):
  parts = auth_dir.split()
  name = parts.pop(0) # the original code had a check that the first part is alphanumeric and of an acceptable length but i know the input it's getting
  flags = []
  while parts[0][0] not in '0123456789':
    flags.append(parts.pop(0))
  addr = parts.pop(0)
  fingerprint = ''.join(parts)
  return name, flags, addr, fingerprint

auth_dirs = [parse_auth_dir(d) for d in auth_dirs]

#conn,KP_relayid_ed,KP_relaysign_ed = connect(('140.78.100.22', 5443))