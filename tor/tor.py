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
import datetime
import pickle
import cryptography.hazmat.primitives.asymmetric.x25519
import secrets

import tor_dirs
import netdoc
import consensus
import routers
import certificate
import lib

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
    payload = lib.bytes_from(FIXED_PAYLOAD_LEN, data, offset)
    offset += FIXED_PAYLOAD_LEN
    return Cell(circuitid, command, payload), data[offset:]
  elif command in variable_length_commands:
    payload_len, = struct.unpack_from('>H', data, offset)
    offset += 2
    payload = lib.bytes_from(payload_len, data, offset)
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

def decode_certs_cell(cell):
  assert cell.command == CERTS, 'attempted to decode non-CERTS cell using decode_certs_cell()'
  n, = struct.unpack_from('>B', cell.payload) # number of certificates
  offset = 1
  certs = {}
  for i in range(n):
    cert_type,cert_len = struct.unpack_from('>BH', cell.payload, offset)
    offset += 3
    cert_data = lib.bytes_from(cert_len, cell.payload, offset)
    offset += cert_len
    if cert_type == IDENTITY_V_SIGNING:
      cert_data = certificate.decode_ed_certificate(cert_data)
      assert cert_data.cert_type == cert_type, f'mismatched certificate type [{cert_data.cert_type}] inside Ed certificate of type 4 in CERTS_CELL'
    if cert_type == SIGNING_V_TLS_CERT:
      cert_data = certificate.decode_ed_certificate(cert_data)
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
  KP_relaysign_ed = certificate.ed_key(certs[IDENTITY_V_SIGNING].key)
  
  assert certs[SIGNING_V_TLS_CERT].key_type in [1, 3], f'incorrect key type {certs[IDENTITY_V_SIGNING].key_type} for SIGNING_V_TLS_CERT certificate' # technically it should be 3, but old tor put 1 for no reason so
  assert certs[SIGNING_V_TLS_CERT].verify(KP_relaysign_ed)
  servercert = s.getpeercert(binary_form = True)
  assert certs[SIGNING_V_TLS_CERT].key == sha256(servercert)
  
  challenge = conn.recv()
  assert challenge.command == AUTH_CHALLENGE
  
  return conn, KP_relaysign_ed # the certificates aren't important right?

def create_first_hop_ntor(conn, fingerprint, ntor_key_pub):
  # ntor_key_pub is B
  # temp_key_pub is X
  # server_temp_key_pub is Y
  
  temp_key_sec = cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey.generate()
  temp_key_pub = temp_key_sec.public_key()
  
  circid = 0x81818181 | secrets.randbits(31) # not sure why i have 0x81818181 - the only thing i need is that the top bit is 1 and the rest are not all 0
  
  conn.send(encode_create2_cell_ntor(circid, fingerprint, ntor_key_pub, temp_key_pub))
  server_temp_key_pub,auth_hashed_server = decode_created2_cell_ntor(conn.recv())
  
  secret_input = temp_key_sec.exchange(server_temp_key_pub) + temp_key_sec.exchange(ntor_key_pub) + fingerprint + ntor_key_pub.public_bytes_raw() + temp_key_pub.public_bytes_raw() + server_temp_key_pub.public_bytes_raw() + NTOR_PROTO_ID
  secret_hashed = tor_hmac(secret_input, NTOR_PROTO_ID + b':verify')
  auth_input = secret_hashed + fingerprint + ntor_key_pub.public_bytes_raw() + server_temp_key_pub.public_bytes_raw() + temp_key_pub.public_bytes_raw() + NTOR_PROTO_ID
  assert auth_hashed == tor_hmac(auth_input, NTOR_PROTO_ID + b':mac')
  
  key_seed = tor_hmac(secret_input, NTOR_PROTO_ID + b':key_extract')
  keys = ntor_kdf(key_seed)
  
  return keys, circid

os.makedirs('cache', exist_ok = True)
os.makedirs('cache/routers', exist_ok = True)

def get_consensus():
  if not os.path.exists('cache/consensus'):
    name,addr,fingerprint = random.choice(tor_dirs.auth_dirs)
    print(f'downloading consensus from {name} ({addr})')
    consensus_response = requests.get(f'http://{addr}/tor/status-vote/current/consensus')
    consensus_data = consensus_response.text
    print(f'response code {consensus_response.status_code}')
    with open('cache/consensus.txt', 'w') as f:
      f.write(consensus_data)
    consensus_doc = netdoc.parse_netdoc(consensus_data)
    consensus_parsed = consensus.parse_consensus(consensus_doc)
    with open('cache/consensus', 'wb') as f:
      pickle.dump(consensus_parsed, f, 0)
  else:
    print('using cached consensus')
    with open('cache/consensus', 'rb') as f:
      consensus_parsed = pickle.load(f)
    if consensus_parsed.valid_until < datetime.datetime.utcnow():
      print('cached consensus too old')
      os.remove('cache/consensus')
      return get_consensus()
  return consensus_parsed

cons = get_consensus() # i can't call it 'consensus' because it'll collide with the module :(

router = random.choice([r for r in cons.routers if 'Guard' in r.flags])

print(f'connecting to {router.name} at {router.address()}')

conn,KP_relaysign_ed = connect(router.address())

def get_router_descriptor(router):
  filename = f'cache/routers/router-{router.name}-{router.ip}-{router.orport}'
  name,addr,fingerprint = random.choice(tor_dirs.auth_dirs)
  print(f'downloading router descriptor for {router.name} ({router.ip}:{router.orport}) from {name} ({addr})')
  router_response = requests.get(f'http://{addr}/tor/server/d/{router.descr_hash.hex()}')
  router_data = router_response.text
  print(f'response code {router_response.status_code}')
  with open(filename + '.txt', 'w') as f:
    f.write(router_data)
  router_doc = netdoc.parse_netdoc(router_data)
  router_parsed = routers.parse_router(router_doc)
  return router_parsed

routerinfo = get_router_descriptor(router)

keys,circid = create_first_hop_ntor(conn, router.id_hash, routerinfo.ntor_key)