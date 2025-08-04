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
import random
import requests
import os
import itertools
import base64
import datetime
import pickle

import tor_dirs

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

# from https://gitlab.torproject.org/tpo/core/tor/-/blob/main/src/app/config/config.c#L5593
def parse_auth_dir(auth_dir):
  parts = auth_dir.split()
  name = parts.pop(0) # the original code had a check that the first part is alphanumeric and of an acceptable length but i know the input it's getting
  flags = []
  while parts[0][0] not in '0123456789':
    flags.append(parts.pop(0))
  addr = parts.pop(0)
  fingerprint = ''.join(parts)
  # i'm going to ignore the flags
  # the ones that are handled in the original code are:
  # hs no-hs bridge no-v2 orport= weight= v3ident= ipv6=
  # upload= download= vote=
  return name, addr, fingerprint # also i have no idea how to verify the fingerprint :(

auth_dirs = [parse_auth_dir(d) for d in tor_dirs.auth_dirs]

os.makedirs('cache', exist_ok = True)

class Peekable:
  def __init__(self, it):
    self.it = iter(it)
    self.buffer = []
  
  def __iter__(self):
    return self
  
  def __next__(self):
    if len(self.buffer) == 1:
      return self.buffer.pop()
    else:
      return next(self.it)
  
  def peek(self):
    if len(self.buffer) == 0:
      self.buffer.append(next(self.it))
    return self.buffer[0]

# convert a function that returns a generator to one that returns a list
def generator_to_list(f):
  return lambda *args, **kwargs: [*f(*args, **kwargs)]

@generator_to_list
def parse_netdoc(netdoc):
  lines = Peekable(line for line in netdoc.split('\n') if line != '')
  for line in lines:
    # parse line as a KeywordLine - keyword + spaces/tabs + arguments
    # i'm assuming i get a well formed document so i don't have to check keyword validity
    # or that whitespace is only spaces and tabs
    # or that there aren't any embedded null characters
    keyword,*arguments = line.split()
    if lines.peek().startswith('-----BEGIN '):
      line = next(lines)
      object_name = line[len('-----BEGIN '):-len('-----')]
      end_line = '-----END ' + object_name + '-----'
      object_encoded = ''.join(itertools.takewhile(lambda line: line != end_line, lines)) # the last line disappears but that's what i want anyway
      object_data = base64.b64decode(object_encoded)
    else:
      object_name = None
      object_data = None
    yield keyword, arguments, object_name, object_data

def get_line_args_optional_no_object(line_type, lines, default = None):
  # assumes lines is a Peekable
  # returns the line arguments or None
  # errors if an object is present
  if lines.peek()[0] == line_type:
    line = next(lines)
    assert line[2] is None, f'line of type {line_type} should not have an object'
    return line[1]
  else:
    return default

def get_line_args_no_object(line_type, lines):
  # lines is a Peekable
  # returns the line arguments
  # errors if an object is present
  check_type = lines.peek()[0]
  assert check_type == line_type, f'missing required line of type {line_type}; got {check_type}'
  line = next(lines)
  assert line[2] is None, f'line of type {line_type} should not have an object'
  return line[1]

# convert a list of 'key=value' strings to a dictionary
def params_to_dict(params):
  if params is None:
    return None
  split = [kv.split('=') for kv in params]
  out = {k:v for k,v in split}
  assert len(out) == len(split), 'duplicate key :('
  return out

def parse_consensus(consensus_doc):
  # consensusdoc is a list of lines, as returned by parse_netdoc()
  # i'm assuming it's in the same order as in the spec at https://spec.torproject.org/dir-spec/consensus-formats.html
  # also that it doesn't have any extra arguments not mentioned in the spec
  lines = Peekable(consensus_doc)
  consensus_version, = get_line_args_no_object('network-status-version', lines)
  assert consensus_version == '3', f'unrecognized consensus version {consensus_version}'
  consensus_type, = get_line_args_no_object('vote-status', lines)
  assert consensus_type == 'consensus', f'unrecognized consensus type {consensus_type}' # the spec says 'vote' or 'status' but the consensus i got has 'consensus'
  consensus_method, = get_line_args_optional_no_object('consensus-method', lines, [1]) # ignore
  
  # these are naive datetime - utc timezone
  valid_after = datetime.datetime.fromisoformat('T'.join(get_line_args_no_object('valid-after', lines)))
  fresh_until = datetime.datetime.fromisoformat('T'.join(get_line_args_no_object('fresh-until', lines)))
  valid_until = datetime.datetime.fromisoformat('T'.join(get_line_args_no_object('valid-until', lines)))
  
  # i don't care about these
  voting_delays = get_line_args_no_object('voting-delay', lines)
  client_versions = get_line_args_no_object('client-versions', lines)
  server_versions = get_line_args_no_object('server-versions', lines)
  
  known_flags = get_line_args_no_object('known-flags', lines)
  
  # i don't care about these
  # maybe the client ones but i'll deal with that if it's a problem
  rec_client_protos = params_to_dict(get_line_args_optional_no_object('recommended-client-protocols', lines, []))
  rec_relay_protos = params_to_dict(get_line_args_optional_no_object('recommended-relay-protocols', lines, []))
  req_client_protos = params_to_dict(get_line_args_optional_no_object('required-client-protocols', lines, []))
  req_relay_protos = params_to_dict(get_line_args_optional_no_object('required-relay-protocols', lines, []))

  params = params_to_dict(get_line_args_optional_no_object('params', lines, []))
  
  srv_prev_reveals,srv_prev = get_line_args_optional_no_object('shared-rand-previous-value', lines)
  srv_prev_reveals = int(srv_prev_reveals)
  srv_prev = base64.b64decode(srv_prev)
  assert len(srv_prev) == 32, f'shared random value of length {len(srv_prev)} in consensus (should be 32)' # 256 bits or 32 bytes
  
  srv_curr_reveals,srv_curr = get_line_args_optional_no_object('shared-rand-current-value', lines)
  srv_curr_reveals = int(srv_curr_reveals)
  srv_curr = base64.b64decode(srv_curr)
  assert len(srv_curr) == 32, f'shared random value of length {len(srv_curr)} in consensus (should be 32)' # 256 bits or 32 bytes
  
  # i don't care about this now
  dirs = []
  while lines.peek()[0] == 'dir-source':
    dir_name,dir_fingerprint,dir_hostname,dir_ip,dir_dirport,dir_orport = get_line_args_no_object('dir-source', lines)
    dir_contact = ' '.join(get_line_args_no_object('contact', lines))
    vote_digest, = get_line_args_no_object('vote-digest', lines) # don't really care about this
    dirs.append((dir_name, dir_fingerprint, dir_hostname, dir_ip, dir_dirport, dir_orport, dir_contact))
  
  routers = []
  while lines.peek()[0] == 'r':
    # i'm ignoring r_descr_digest (digest of most recent descriptor), r_pub1, r_pub2 (publication date, only meaningful in votes)
    r_name,r_id_hash,r_descr_digest,r_pub1,r_pub2,r_ip,r_orport,r_dirport = get_line_args_no_object('r', lines)
    r_id_hash = base64.b64decode(r_id_hash + '=') # unpadded :(
    addrs = [] # ignore
    while lines.peek()[0] == 'a':
      r_extra_addr, = get_line_args_no_object('a', lines)
      addrs.append(r_extra_addr)
    r_flags = get_line_args_no_object('s', lines)
    r_version = ' '.join(get_line_args_optional_no_object('v', lines, []))
    r_protos = params_to_dict(get_line_args_no_object('pr', lines))
    r_bandwidth = params_to_dict(get_line_args_optional_no_object('w', lines)) # ignore
    r_ports = get_line_args_optional_no_object('p', lines)
    routers.append((r_name, r_id_hash, r_ip, r_orport, r_dirport, r_flags, r_version, r_protos, r_ports))
  
  () = get_line_args_no_object('directory-footer', lines)
  bandwidth_weights = params_to_dict(get_line_args_optional_no_object('bandwidth-weights', lines)) # ignore
  
  signatures = [] # ignore # i'm not verifying these :)
  for line in lines:
    assert line[0] == 'directory-signature'
    signature_data = line[1]
    assert line[2] == 'SIGNATURE'
    if len(signature_data) == 3:
      hash_alg,id_key,signing_key_digest = signature_data
    else:
      hash_alg,id_key,signing_key_digest = 'sha1', *signature_data
    signatures.append((hash_alg, id_key, signing_key_digest, line[3]))
  
  return valid_after, fresh_until, valid_until, known_flags, rec_client_protos, req_client_protos, params, srv_prev, srv_curr, routers

def get_consensus():
  if not os.path.exists('cache/consensus'):
    name,addr,fingerprint = random.choice(auth_dirs)
    print(f'downloading consensus from {name} ({addr})')
    consensus_data = requests.get(f'http://{addr}/tor/status-vote/current/consensus').text
    consensus_doc = parse_netdoc(consensus_data)
    consensus = parse_consensus(consensus_doc)
    with open('cache/consensus', 'wb') as f:
      pickle.dump(consensus, f, 0)
  else:
    print('using cached consensus')
    with open('cache/consensus', 'rb') as f:
      consensus = pickle.load(f)
    valid_until = consensus[2]
    if valid_until < datetime.datetime.utcnow():
      print('cached consensus too old')
      os.remove('cache/consensus')
      return get_consensus()
  return consensus

valid_after,fresh_until,valid_until,known_flags,rec_client_protos,req_client_protos,params,srv_prev,srv_curr,routers = get_consensus()

router = random.choice([r for r in routers if 'Guard' in r[5]])

#conn,KP_relayid_ed,KP_relaysign_ed = connect(('140.78.100.22', 5443))