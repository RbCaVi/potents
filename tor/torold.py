# NOTE: i can't figure out how to get the hsdir to find
# there's at least 2 places the problem could be
# getblindkey() - i have no idea how to multiply an ed25519 point properly
# the bit at the end - is it the right path to find it? - is it base64? does it have a .z?
# the part before it - am i implementing the hsdir selection algorithm correctly?

# i do have "working" tor proxy though :)

# died at 23:30 Apr 11, 2025 AD


# preliminaries
# https://spec.torproject.org/tor-spec/preliminaries.html

# KP -- a public key for an asymmetric cipher.
# KS -- a private key for an asymmetric cipher.
# K  -- a key for a symmetric cipher.
# N  -- a "nonce", a random value, usually deterministically chosen from other inputs using hashing.

# KP_ENC_LEN -- the length of a public-key encrypted message, in bytes.
# KP_PAD_LEN -- the number of bytes added in padding for public-key
#   encryption, in bytes. (The largest number of bytes that can be encrypted
#   in a single public-key operation is therefore KP_ENC_LEN-KP_PAD_LEN.)

# DH_LEN -- the number of bytes used to represent a member of the
#   Diffie-Hellman group.
# DH_SEC_LEN -- the number of bytes used in a Diffie-Hellman private key (x).

# Name                  Length in bytes Meaning
# CELL_BODY_LEN         509             The body length for a fixed-length cell
# CIRCID_LEN(v), v < 4  2               The length of a circuit ID
# CIRCID_LEN(v), v ≥ 4  4
# CELL_LEN(v), v < 4    512             The length of a fixed-length cell
# CELL_LEN(v), v ≥ 4    514

# Formerly CELL_BODY_LEN was called sometimes called PAYLOAD_LEN.
CELL_BODY_LEN = 509

def CIRCID_LEN(v):
  if v < 4:
    return 2
  return 4

# Note that for all v, CELL_LEN(v) = 1 + CIRCID_LEN(v) + CELL_BODY_LEN.
def CELL_LEN(v):
  return 1 + CIRCID_LEN(v) + CELL_BODY_LEN


# Ciphers

# These are the ciphers we use unless otherwise specified.
# Several of them are deprecated for new use.

# For a stream cipher, unless otherwise specified,
# we use 128-bit AES in counter mode,
# with an IV of all 0 bytes. (We also require AES256.)
# (stream cipher is 128 bit AES - counter mode - IV all 0s - AES256? - rbcavi)

# For a public-key cipher, unless otherwise specified,
# we use RSA with 1024-bit keys and a fixed exponent of 65537.
# We use OAEP-MGF1 padding, with SHA-1 as its digest function.
# We leave the optional “Label” parameter unset.
# (For OAEP padding, see ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-1/pkcs-1v2-1.pdf)
# (public key cipher is RSA - 1024 bit keys - exponent 65537 - OAEP MGF1 padding SHA1 digest - Label unset - rbcavi)

# We also use the Curve25519 group and the Ed25519 signature format in several places.

# For Diffie-Hellman, unless otherwise specified, we use a generator (g) of 2.
# For the modulus (p), we use the 1024-bit safe prime from rfc2409 section 6.2 whose hex representation is
# FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74
# 020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437
# 4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED
# EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF

# (A (how do Diffie-Hellman in python???????) - rbcavi)

# As an optimization, implementations SHOULD choose DH private keys (x) of 320 bits.
# Implementations that do this MUST never use any DH key more than once.
# [May other implementations reuse their DH keys?? -RD]
# [Probably not. Conceivably, you could get away with changing DH keys once per second,
# but there are too many oddball attacks for me to be comfortable that this is safe. -NM]
# (NEVER REUSE DIFFIE HELLMAN KEYS - rbcavi)

# KEY_LEN=16. DH_LEN=128; DH_SEC_LEN=40. KP_ENC_LEN=128; KP_PAD_LEN=42.

KEY_LEN = 16
DH_LEN = 128
DH_SEC_LEN = 40
KP_ENC_LEN = 128
KP_PAD_LEN = 42

# All "random" values MUST be generated with a cryptographically strong pseudorandom number generator
# seeded from a strong entropy source, unless otherwise noted.
# All "random" values MUST be selected uniformly at random
# from the universe of possible values, unless otherwise noted.
# (oh no (how do i do that??) - rbcavi)



import hashlib
# Cryptographic hash functions

# Tor uses the cryptographic hash functions SHA-1, SHA-256, and SHA3-256.

# NOTE: (- rbcavi)
# SHA-1 is vulnerable to various collision attacks, and should not be used anywhere new.
# Its existing applications are redundant with other hash functions, deprecated, or both.
# (sure sure whatever you say - rbcavi)


# We denote applications of these hash functions to some message M as:
# SHA1(M)
# SHA256(M)
# SHA3_256(M)

def SHA1(M):
  print("SHA1 is deprecated :((((((((((")
  return hashlib.sha1(M).digest()

def SHA256(M):
  return hashlib.sha256(M).digest()

def SHA3_256(M):
  return hashlib.sha3_256(M).digest()

# We define constants to represent the lengths in bytes of the digests that these functions output:

SHA1_LEN = 20
SHA256_LEN = 32
SHA3_256_LEN = 32

assert SHA1_LEN == hashlib.sha1().digest_size
assert SHA256_LEN == hashlib.sha256().digest_size
assert SHA3_256_LEN == hashlib.sha3_256().digest_size

# Note that although the above terminology is preferred,
# many of our older specifications have not yet been converted to use it.
# In some places, we also use H(M) to mean “the digest of M”,
# and DIGEST_LEN or HASH_LEN to refer to the length of that digest.
# Unless otherwise specified, H(M) is computed using SHA-1.

H = SHA1


# Computing the digest of an RSA key

# When key is an RSA public key, we use the notation DER(key) to denote
# the ASN.1 DER encoding of the key’s representation as a PKCS#1 RSAPublicKey object.

# Some older text does not use yet this notation.
# When we refer to “the digest of an RSA public key”,
# unless otherwise specified, we mean a digest of DER(key).
# The hash function should be specified explicitly.

# https://stackoverflow.com/a/54549675
import cryptography.hazmat.primitives.serialization

def DER(key):
  return key.public_bytes(
    encoding = cryptography.hazmat.primitives.serialization.Encoding.DER,
    #format = cryptography.hazmat.primitives.serialization.PublicFormat.SubjectPublicKeyInfo,
  )



# Relay keys and identities

# Every Tor relay has multiple public/private keypairs,
# with different lifetimes and purposes. We explain them here.

# Each key here has an English name (like “Ed25519 identity key”)
# and an unambiguous identifier (like KP_relayid_ed).

# In an identifier, a KP_ prefix denotes a                 public key,
#               and a KS_ prefix denotes the corresponding secret key.

# (NOTE: -rbcavi)
# For historical reasons or reasons of space,
# you will sometimes encounter multiple English names for the same key,
# or shortened versions of that name.
# The identifier for a key, however, should always be unique and unambiguous.

# For security reasons, all keys MUST be distinct:
# the same key or keypair should never be used
# for separate roles within the Tor protocol suite,
# unless specifically stated.
# For example, a relay’s identity key KP_relayid_ed MUST NOT
# also be used as its medium-term signing key KP_relaysign_ed.
# (DON'T REUSE KEYS - rbcavi)


# Identity keys

# An identity key is a long-lived key that uniquely identifies a relay.
# Two relays with the same set of identity keys are considered to be the same;
# any relay that changes its identity key is considered to have become a different relay.
# (identity keys identify the relay (that's why it's called _relayid) - rbcavi)

# An identity keypair’s lifetime is the same as the lifetime of the relay. (should be? - rbcavi)

# Two identity keys are currently defined:
# (two identity keys - _relayid_(ed/rsa) - rbcavi)

# (KP/KS)_relayid_ed: An “ed25519 identity key”, also sometimes called a “master identity key”.
# This is an Ed25519 key. This key never expires.
# It is used for only one purpose: signing the KP_relaysign_ed key,
# which is used to sign other important keys and objects.
# (_relayid_ed - ed25519 - rbcavi)

# (KP/KS)_relayid_rsa: A legacy “RSA identity key”.
# This is an RSA key. It never expires.
# It is always 1024 bits long, and (as discussed above) its exponent must be 65537.
# It is used to sign directory documents and certificates.
# (_relayid_rsa - RSA - 1024 bits - exponent 65537 - rbcavi)

# Note that because the legacy RSA identity key is so short,
# it should not be assumed secure against an attacker.
# It exists for legacy purposes only.
# When authenticating a relay, a failure to prove an expected RSA identity
# is sufficient evidence of a failure to authenticate,
# but a successful proof of an RSA identity is not sufficient to establish a relay’s identity.
# Parties SHOULD NOT use the RSA identity on its own.
# (_relayid_rsa is NOT proof of identity - rbcavi)

# We write KP_relayid to refer to a key which is either KP_relayid_rsa or KP_relayid_ed.
# (_relayid means _relayid_(ed/rsa) - rbcavi)


# Online signing keys

# Since Tor’s design tries to support keeping the high-value Ed25519 relay identity key offline,
# we need a corresponding key that can be used for online signing:
# (_relaysign_ed - more public extension of _relayid_ed - signs everything else - rbcavi)

# (KP/KS)_relaysign_ed: A medium-term Ed25519 “signing” key.
# This key is signed by the identity key KP_relayid_ed, and must be kept online.
# A new one should be generated periodically.
# It signs nearly everything else, including directory objects and certificates for other keys.
# (doesn't _relayid_rsa do this too? - rbcavi)
# (_relaysign_ed - ed25519 - signed by KP_relayid_ed - signs everything else - rbcavi)

# When this key is generated, it needs to be signed with the KP_relayid_ed key,
# producing a certificate of type IDENTITY_V_SIGNING. The KP_relayid_ed key is not used for anything else.
# (check out https://spec.torproject.org/cert-spec.html - rbcavi)
# (_relaysign_ed - signed by KP_relayid_ed - IDENTITY_V_SIGNING certificate - rbcavi)


# Circuit extension keys

# Each relay has one or more circuit extension keys (also called “onion keys”).
# When creating or extending a circuit, a client uses this key to perform
# a one-way authenticated key exchange with the target relay.
# If the recipient does not have the correct private key, the handshake will fail.
# (circuit extension keys - used to add relays to the chain - rbcavi)

# Circuit extension keys have moderate lifetimes, on the order of weeks.
# They are published as part of the directory protocol,
# and relays SHOULD accept handshakes for a while after publishing any new key.
# (The exact durations for these are set via a set of network parameters.)

# There are two current kinds of circuit extension keys:

# (KP/KS)_ntor: A curve25519 key used for the ntor and ntorv3 circuit extension handshakes.
# (_ntor - curve25519 - ntor and ntorv3 - rbcavi)

# (KP/KS)_onion_tap: A 1024 bit RSA key used for the obsolete TAP circuit extension handshake.
# (_onion_tap - RSA - 1024 bit - TAP - obsolete - rbcavi)


# Family keys

# When a group of relays are controlled by the same operator(s), we call them a “family”. A family has a keypair:

# (KP/KS)_familyid_ed: An ed25519 key used to prove membership in a family by signing a family certificate.
# (_familyid_ed - ed25519 - shows owner of a relay - rbcavi)


# Channel authentication

# There are other keys that relays use to authenticate as part of their channel negotiation handshakes.

# These keys are authenticated with other, longer lived keys.
# Relays MAY rotate them as often as they like,
# and SHOULD rotate them frequently—typically, at least once a day.

# (KP/KS)_link_ed. A short-term Ed25519 “link authentication” key,
# used to authenticate the link handshake: see “Negotiating and initializing channels”.
# This key is signed by the “signing” key, and should be regenerated frequently.
# (_link_ed - signed by _relaysign_ed - rbcavi)
# (check out https://spec.torproject.org/tor-spec/negotiating-channels.html#negotiating - rbcavi)

# Legacy channel authentication
# (there's also some keys used by older tor - rbcavi)

# These key types were used in older versions of the channel negotiation handshakes.

# (KP/KS)_legacy_linkauth_rsa: A 1024-bit RSA key, used to authenticate the link handshake.
# (No longer used in modern Tor.) It played a role similar to KP_link_ed.

# As a convenience, to describe legacy versions of the link handshake,
# we give a name to the public key used for the TLS handshake itself:

# (KP/KS)_legacy_conn_tls: A short term key used to for TLS connections.
# (No longer used in modern Tor.) This was another name for the server’s TLS key,
# which at the time was required to be an RSA key. It was used in some legacy handshake versions.


# Channels

# A channel is a direct encrypted connection between two Tor relays, or between a client and a relay.

# Channels are implemented as TLS sessions over TCP.

# Clients and relays may both open new channels; only a relay may be the recipient of a channel.

# As part of establishing a channel, the responding relay will always prove cryptographic ownership
# of one or more relay identities, using a handshake that combines TLS facilities and a series of Tor cells.

# As part of this handshake, the initiator MAY also prove cryptographic ownership
# of its own relay identities, if it has any: public relays SHOULD prove their
# identities when they initiate a channel, whereas clients and bridges SHOULD NOT do so.

# Parties should usually reuse an existing channel rather than opening new a channel to the same relay.
# There are exceptions here; we discuss them more below.

# To open a channel, a client or relay must know the IP address and port of the target relay.
# (This is sometimes called the “OR address” or “OR port” for the relay.) In most cases,
# the participant will also know one or more expected identities for the target relay,
# and will reject the channel if the target relay cannot cryptographically prove ownership of those identities.

# (NOTE: - rbcavi)
# When initiating a connection, if a reasonably live consensus is available,
# then the expected identity key is taken from that consensus.
# But when initiating a connection otherwise, the expected identity key
# is the one given in the hard-coded authority or fallback list.
# Finally, when creating a connection because of an EXTEND/EXTEND2 message,
# the expected identity key is the one given in the message.

# Opening a channel is multi-step process:

# The initiator opens a new TLS session with certain properties,
# and the responding relay checks and enforces those properties.
# Both parties exchange cells over this TLS session in order to establish their identity or identities.
# Both parties verify that the identities that they received are the ones that they expected.
# (If any expected key is missing or not as expected, the party MUST close the connection.)

# Once this is done, the channel is Open, and regular cells can be exchanged.


# Channel lifetime

# Channels are not permanent.
# Either side MAY close a channel if there are no circuits running on it
# and an amount of time (KeepalivePeriod, defaults to 5 minutes)
# has passed since the last time any traffic was transmitted over it.
# Clients SHOULD also hold a TLS connection with no circuits open,
# if it is likely that a circuit will be built soon using that connection.



# Cells (messages on channels)

# The basic unit of communication on a Tor channel is a “cell”.

# Once a TLS connection is established, the two parties send cells to each other.
# Cells are sent serially, one after another.

# Cells may be sent embedded in TLS records of any size,
# or divided across TLS records, but the framing of TLS records
# MUST NOT leak information about the type or contents of the cells.
# (like i can control that - rbcavi)

# Most cells are of fixed length, with the actual length depending on the negotiated link protocol on the channel.
# Below we designate the negotiated protocol as v.

# As an exception, VERSIONS cells are always sent with v = 0, since no version has yet been negotiated.

# A fixed-length cell has this format:
# Field   Size in bytes Notes
# CircID  CIRCID_LEN(v)
# Command 1
# Body    CELL_BODY_LEN Padded to fit
# (i'm assuming CircID is big endian, though it probably doesn't matter [it's just for id purposes right?] - rbcavi)

# The value of CIRCID_LEN depends on the negotiated link protocol.
# (i have a function for that up above - rbcavi)

import struct

def unpackstart(fmt, data):
  # i really like this function
  if len(data) < struct.calcsize(fmt):
    return None, data
  return struct.unpack(fmt,data[:struct.calcsize(fmt)]),data[struct.calcsize(fmt):]

def splitat(i, data):
  if len(data) < i:
    return None, data
  return data[:i],data[i:]

def readcircuitid(data, v):
  circuitid = 0
  if len(data) < CIRCID_LEN(v):
    return None, data
  for _ in range(CIRCID_LEN(v)):
    (byte,),data = unpackstart(">B", data) # don't need to check the return because of the check above
    circuitid = circuitid << 8 + byte
  return circuitid, data

def writecircuitid(circuitid, v):
  data = b''
  for _ in range(CIRCID_LEN(v)):
    data = struct.pack("B", circuitid % 256) + data
    circuitid = circuitid >> 8
  return data

def pad(data, length):
  assert len(data) <= length
  return data + b'\0' * (length - len(data)) # pad with 0 bytes (it'll be fine right?)

class Cell:
  def __init__(self, circuitid, command, body):
    self.circuitid = circuitid
    self.command = command
    self.body = body

  def __repr__(self):
    return f'Cell({self.circuitid}, {self.command}, {self.body})'

def readfixedlengthcell(data, v):
  # idk if this should take a socket or something
  # i'll just return None if there's not enough data
  if len(data) < CELL_LEN(v):
    return None, data
  # don't need to check the returns because of the check above
  circuitid,data = readcircuitid(data, v)
  (command,),data = unpackstart(">B", data)
  body,data = splitat(CELL_BODY_LEN, data)
  return Cell(circuitid, command, body), data

def writefixedlengthcell(cell, v):
  # idk if this should take a socket or something
  data = writecircuitid(cell.circuitid, v)
  data += struct.pack(">B", cell.command)
  data += pad(cell.body, CELL_BODY_LEN)
  return data

# Some cells have variable length; the length of these cells is encoded in their header.

# A variable-length cell has this format:
# Field   Size in bytes Notes
# CircID  CIRCID_LEN(v)
# Command 1
# Length  2             A big-endian integer
# Body    Length

def readvariablelengthcell(data, v):
  # idk if this should take a socket or something
  # i'll just return None if there's not enough data
  if len(data) < CIRCID_LEN(v) + 1 + 2: # circuit id + command + length
    return None, data
  circuitid,data = readcircuitid(data, v)
  (command,length),data = unpackstart(">BH", data)
  if len(data) < length:
    return None, data
  body,data = splitat(length, data)
  return Cell(circuitid, command, body), data

def writevariablelengthcell(cell, v):
  # idk if this should take a socket or something
  data = writecircuitid(cell.circuitid, v)
  data += struct.pack(">BH", cell.command, len(cell.body))
  data += cell.body
  return data

# Fixed-length and variable-length cells are distinguished based on the value of their Command field:

# Command 7 (VERSIONS) is variable-length.
# Every other command less than 128 denotes a fixed-length cell.
# Every command greater than or equal to 128 denotes a variable-length cell.
# (command <128 = fixed length [except VERSIONS [7] is variable length] - rbcavi)

def isvariablelength(command):
  if command == VERSIONS:
    return True
  if command < 128:
    return False
  return True

def readcell(data, v):
  if len(data) < CIRCID_LEN(v) + 1: # circuit id + command
    return None, data
  # why did i duplicate these two lines in three places?????
  circuitid,data_ = readcircuitid(data, v)
  (command,),_ = unpackstart(">B", data_)
  if isvariablelength(command):
    return readvariablelengthcell(data, v)
  else:
    return readfixedlengthcell(data, v)

def writecell(cell, v):
  if isvariablelength(cell.command):
    return writevariablelengthcell(cell, v)
  else:
    return writefixedlengthcell(cell, v)


# The Command field of a fixed-length cell holds one of the following values:
# Value C P Identifier        Description
# 0     N   PADDING           Link Padding
# 1     Y   CREATE            Create circuit (deprecated)
# 2     Y   CREATED           Acknowledge CREATE (deprecated)
# 3     Y   RELAY             End-to-end data
# 4     Y   DESTROY           Destroy circuit
# 5     Y   CREATE_FAST       Create circuit, no public key
# 6     Y   CREATED_FAST      Acknowledge CREATE_FAST
# 8     N   NETINFO           Time and address info
# 9     Y   RELAY_EARLY       End-to-end data; limited
# 10    Y   CREATE2           Create circuit
# 11    Y   CREATED2          Acknowledge CREATED2
# 12    Y 5 PADDING_NEGOTIATE Padding negotiation

# The variable-length Command values are:
# Value C P   Identifier  Description
# 7     N     VERSIONS  Negotiate link protocol
# 128   N     VPADDING  Variable-length padding
# 129   N     CERTS Certificates
# 130   N     AUTH_CHALLENGE  Challenge value
# 131   N     AUTHENTICATE  Authenticate initiator
# 132   N n/a AUTHORIZE (Reserved)


PADDING             = 0   # Link Padding
#CREATE             = 1   # Create circuit (deprecated)
#CREATED            = 2   # Acknowledge CREATE (deprecated)
RELAY               = 3   # End-to-end data
DESTROY             = 4   # Destroy circuit
CREATE_FAST         = 5   # Create circuit, no public key
CREATED_FAST        = 6   # Acknowledge CREATE_FAST
NETINFO             = 8   # Time and address info
RELAY_EARLY         = 9   # End-to-end data; limited
CREATE2             = 10  # Create circuit
CREATED2            = 11  # Acknowledge CREATED2
PADDING_NEGOTIATE   = 12  # Padding negotiation

VERSIONS            = 7   # Negotiate link protocol
VPADDING            = 128 # Variable-length padding
CERTS               = 129 # Certificates
AUTH_CHALLENGE      = 130 # Challenge value
AUTHENTICATE        = 131 # Authenticate initiator
#AUTHORIZE          = 132 # (Reserved)

# Negotiating and initializing channels

# Here we describe the primary TLS behavior used by Tor relays and clients to create a new channel.
# There are older versions of these handshakes, which we describe in another section.

# In brief:

# The initiator starts the handshake by opening a TLS connection.
# Both parties send a VERSIONS to negotiate the link protocol version to use.
# The responder sends a CERTS cell to give the initiator the certificates it needs to learn the responder’s identity,
# an AUTH_CHALLENGE cell that the initiator must include as part of its answer if it chooses to authenticate,
# and a NETINFO cell to establish clock skew and IP addresses.
# The initiator checks whether the CERTS cell is correct, and decides whether to authenticate.
# If the initiator is not authenticating itself, it sends a NETINFO cell.
# If the initiator is authenticating itself, it sends a CERTS cell, an AUTHENTICATE cell, a NETINFO cell.
# (>open TLS >VERSIONS <VERSIONS+<CERTS+<AUTH_CHALLENGE+<NETINFO (check CERTS) >NETINFO / >CERTS+>AUTHENTICATE+>NETINFO - rbcavi)


# When this handshake is in use, the first cell must be VERSIONS, VPADDING, or AUTHORIZE,
# and no other cell type is allowed to intervene besides those specified, except for VPADDING cells.

# (The AUTHORIZE cell type is reserved for future use by scanning-resistance designs. It is not specified here.)

# The TLS handshake

# The initiator must send a ciphersuite list containing at least one ciphersuite other than those listed in the obsolete v1 handshake.

# This is trivially achieved by using any modern TLS implementation, and most implementations will not need to worry about it.

# This requirement distinguishes the current protocol (sometimes called the “in-protocol” or “v3” handshake)
# from the obsolete v1 protocol.


# TLS security considerations

# (Standard TLS security guarantees apply; this is not a comprehensive guide.)

# Implementations SHOULD NOT allow TLS session resumption –
# it can exacerbate some attacks (e.g. the “Triple Handshake” attack from Feb 2013),
# and it plays havoc with forward secrecy guarantees.

# Implementations SHOULD NOT allow TLS compression –
# although we don’t know a way to apply a CRIME-style attack
# to current Tor directly, it’s a waste of resources.

# (like i care about security here - rbcavi)


# Negotiating versions with VERSIONS cells

# There are multiple instances of the Tor channel protocol.

# Once the TLS handshake is complete, both parties send a VERSIONS cell to negotiate which one they will use.

# The body in a VERSIONS cell is a series of big-endian two-byte integers.
# Both parties MUST select as the link protocol version the highest number
# contained both in the VERSIONS cell they sent and in the VERSIONS cell they received.
# If they have no such version in common, they cannot communicate and MUST close the connection.
# Either party MUST close the connection if the VERSIONS cell is not well-formed
# (for example, if the body contains an odd number of bytes).

# Any VERSIONS cells sent after the first VERSIONS cell MUST be ignored.
# To be interpreted correctly, later VERSIONS cells MUST have a CIRCID_LEN
# matching the version negotiated with the first VERSIONS cell.

# The obsolete v1 channel protocol does note VERSIONS cells.
# Implementations MUST NOT list version 1 in their VERSIONS cells.
# The obsolete v2 channel protocol can only be used after renegotiation;
# implementations MUST NOT list version 2 in their VERSIONS cells unless they have renegotiated the TLS session.
# (nah i don't care about these "obsolete" versions)

# The currently specified Link protocols are:
# Version Description
# 1 (Obsolete) The “certs up front” handshake.
# 2 (Obsolete) Uses the renegotiation-based handshake. Introduces variable-length cells.
# 3 (Obsolete) Begins use of the current (“in-protocol”) handshake.
# 4 Increases circuit ID width to 4 bytes.
# 5 Adds support for link padding and negotiation.


# Certificate types (CERT_TYPE field)

# This table shows values of the CERT_TYPE field in Ed,
# as well as values of the CertType field used in a CERTS cell during channel negotiation.

# Type  Mnemonic             Format Subject                Signing key     Reference                  Notes
# [01]  TLS_LINK_X509        X.509  KP_legacy_conn_tls     KS_relayid_rsa  Legacy channel negotiation Obsolete
# [02]  RSA_ID_X509          X.509  KP_relayid_rsa         KS_relayid_rsa  Legacy channel negotiation Obsolete
# [03]  LINK_AUTH_X509       X.509  KP_legacy_linkauth_rsa KS_relayid_rsa  Legacy channel negotiation Obsolete
# [04]  IDENTITY_V_SIGNING   Ed     KP_relaysign_ed        KS_relayid_ed   Online signing keys 
# [05]  SIGNING_V_TLS_CERT   Ed     A TLS certificate      KS_relaysign_ed CERTS cells 
# [06]  SIGNING_V_LINK_AUTH  Ed     KP_link_ed             KS_relaysign_ed CERTS cells 
# [07]  RSA_ID_V_IDENTITY    Rsa    KP_relayid_ed          KS_relayid_rsa  CERTS cells 
# [08]  BLINDED_ID_V_SIGNING Ed     KP_hs_desc_sign        KS_hs_blind_id  HsDesc (outer)  
# [09]  HS_IP_V_SIGNING      Ed     KP_hs_ipt_sid          KS_hs_desc_sign HsDesc (auth-key)          Backwards, see note 1
# [0A]  NTOR_CC_IDENTITY     Ed     KP_relayid_ed          EdCvt(KS_ntor)  ntor cross-cert 
# [0B]  HS_IP_CC_SIGNING     Ed     KP_hss_ntor            KS_hs_desc_sign HsDesc (enc-key-cert)      Backwards, see note 1
# [0C]  FAMILY_V_IDENTITY    Ed     KP_relayid_ed          KS_familyid_ed  family-cert 

# Note 1: The certificate types [09] HS_IP_V_SIGNING and [0B] HS_IP_CC_SIGNING were implemented incorrectly,
# and now cannot be changed. Their signing keys and subject keys, as implemented, are given in the table.
# They were originally meant to be the inverse of this order.

TLS_LINK_X509        = 0x01
RSA_ID_X509          = 0x02
LINK_AUTH_X509       = 0x03
IDENTITY_V_SIGNING   = 0x04
SIGNING_V_TLS_CERT   = 0x05
SIGNING_V_LINK_AUTH  = 0x06
RSA_ID_V_IDENTITY    = 0x07
BLINDED_ID_V_SIGNING = 0x08
HS_IP_V_SIGNING      = 0x09
NTOR_CC_IDENTITY     = 0x0A
HS_IP_CC_SIGNING     = 0x0B
FAMILY_V_IDENTITY    = 0x0C

import ssl

def getcontext():
  context = ssl.create_default_context()
  context.check_hostname = False
  context.verify_mode = ssl.VerifyMode.CERT_NONE
  return context

def toversionscell(versions):
  # a VERSIONS cell should have a circuitid of 0
  return Cell(0, VERSIONS, b''.join(struct.pack(">H", version) for version in versions))

def fromversionscell(cell):
  assert cell.command == VERSIONS
  return {v for v, in struct.iter_unpack(">H", cell.body)}

class Cert:
  def __init__(self, ctype, certdata):
    self.type = ctype
    self.certdata = certdata
    self.ised = self.type in [0x04, 0x05, 0x06, 0x08, 0x09, 0x0A, 0x0B, 0x0C]
    if self.ised: # ed25519 certificates
      (version,ctype2,expire,keytype,key,extcount),rest = unpackstart('>BBIB32sB', self.certdata)
      assert version == 1
      assert ctype2 == self.type
      assert expire > int(time.time()) // 3600
      # ignore keytype
      self.key = key
      self.exts = []
      for i in range(extcount):
        (elen,etype,eflags),rest = unpackstart('>HBB', rest)
        edata,rest = splitat(elen, rest)
        self.exts.append((etype, eflags, edata))
      assert len(rest) == 64
      self.signed = self.certdata[:-64]
      self.signature = rest

  def __repr__(self):
    if not self.ised:
      return f'Cert({self.type}, {self.certdata})'
    else:
      return f'EdCert({self.type}, {self.key}, {self.exts}, {self.signature})'

def readcert(data):
  (ctype,length),data = unpackstart(">BH", data)
  cert,data = splitat(length, data)
  return Cert(ctype, cert), data

def fromcertscell(cell):
  assert cell.command == CERTS
  (n,),data = unpackstart(">B", cell.body)
  certs = []
  for _ in range(n):
    cert,data = readcert(data)
    certs.append(cert)
  # make sure the certificate types are unique
  assert len({cert.type for cert in certs}) == len(certs)
  return {cert.type:cert for cert in certs}

def readaddr(data):
    (atype,alen),data = unpackstart(">BB", data)
    assert (atype, alen) in [(4, 4), (6, 16)]
    addr,data = splitat(alen, data)
    if atype == 4:
      addr = f'{addr[0]}.{addr[1]}.{addr[2]}.{addr[3]}'
    if atype == 6:
      addr = (
        f'{hex(0x10000 + addr[0x0] * 0x100 + addr[0x1])[3:]}:'
        f'{hex(0x10000 + addr[0x2] * 0x100 + addr[0x3])[3:]}:'
        f'{hex(0x10000 + addr[0x4] * 0x100 + addr[0x5])[3:]}:'
        f'{hex(0x10000 + addr[0x6] * 0x100 + addr[0x7])[3:]}:'
        f'{hex(0x10000 + addr[0x8] * 0x100 + addr[0x9])[3:]}:'
        f'{hex(0x10000 + addr[0xa] * 0x100 + addr[0xb])[3:]}:'
        f'{hex(0x10000 + addr[0xc] * 0x100 + addr[0xd])[3:]}:'
        f'{hex(0x10000 + addr[0xe] * 0x100 + addr[0xf])[3:]}'
      ).upper()
    return addr, data

def fromnetinfocell(cell):
  assert cell.command == NETINFO
  (ts,),data = unpackstart(">I", cell.body)
  oaddr,data = readaddr(data)
  (n,),data = unpackstart(">B", data)
  myaddrs = []
  for _ in range(n):
    myaddr,data = readaddr(data)
    myaddrs.append(myaddr)
  return (ts, oaddr, myaddrs)

def tonetinfocell(addr):
  # a NETINFO cell should have a circuitid of 0
  addr = [int(c) for c in addr.split('.')]
  # "Clients SHOULD send [00 00 00 00] as their timestamp, to avoid fingerprinting."
  #return Cell(0, NETINFO, struct.pack(">IBB4BB", int(time.time()), 4, 4, *addr, 0))
  return Cell(0, NETINFO, struct.pack(">IBB4BB", 0, 4, 4, *addr, 0))

import time

class CellSocket:
  def __init__(self, conn):
    self.conn = conn
    self.buffer = b''
    self.version = 0

  def recv(self):
    cell,self.buffer = readcell(self.buffer, self.version)
    if cell is not None:
      return cell
    while True:
      #print("whop")
      chunk = self.conn.recv(2048)
      if chunk != b'':
        self.buffer += chunk
        cell,self.buffer = readcell(self.buffer, self.version)
        if cell is not None:
          if cell.command != PADDING:
            return cell
          else:
            print("padding", cell)
      else:
        print(self.buffer)
        time.sleep(1)
        print("Not enough data for a complete cell, waiting...")
        # uhh timeout maybe???

  def send(self, cell):
    self.conn.send(writecell(cell, self.version))

import socket
import nacl.encoding
import nacl.signing
import cryptography.x509

# (>open TLS >VERSIONS <VERSIONS+<CERTS+<AUTH_CHALLENGE+<NETINFO (check CERTS) >NETINFO / >CERTS+>AUTHENTICATE+>NETINFO - rbcavi)
# (but i'm not authenticating - rbcavi)
# (>open TLS >VERSIONS <VERSIONS+<CERTS+<AUTH_CHALLENGE+<NETINFO (check CERTS) >NETINFO - rbcavi)
def connect(server, port, context = getcontext()):
  sock = context.wrap_socket(socket.socket(socket.AF_INET))
  sock.connect((server, port))
  conn = CellSocket(sock)

  versions = {4} # the supported versions (just 4 for now)
  conn.send(toversionscell(versions)) # the initial VERSIONS cell is sent with link version 0 (default in CellSocket)

  rversions = fromversionscell(conn.recv()) # the responder's supported versions # recieved with version 0 too

  print('our versions:', versions)
  print('their versions:', rversions)

  conn.version = max(versions & rversions) # this is the version we're using

  rcerts = fromcertscell(conn.recv()) # the responder's certificates

  #print(rcerts)
  print(rcerts.keys())
  KP_relayid_ed = nacl.signing.VerifyKey(rcerts[IDENTITY_V_SIGNING].exts[0][2], encoder = nacl.encoding.RawEncoder)
  KP_relayid_ed.verify(rcerts[IDENTITY_V_SIGNING].signed, rcerts[IDENTITY_V_SIGNING].signature)
  KP_relaysign_ed = nacl.signing.VerifyKey(rcerts[IDENTITY_V_SIGNING].key, encoder = nacl.encoding.RawEncoder)
  KP_relaysign_ed.verify(rcerts[SIGNING_V_TLS_CERT].signed, rcerts[SIGNING_V_TLS_CERT].signature)
  servercert = cryptography.x509.load_der_x509_certificate(sock.getpeercert(binary_form = True))
  assert rcerts[SIGNING_V_TLS_CERT].key == SHA256(DER(servercert))

  challenge = conn.recv()
  assert challenge.command == AUTH_CHALLENGE

  netinfo = fromnetinfocell(conn.recv())
  print(time.time() - netinfo[0])
  conn.send(tonetinfocell(server))

  return (conn, KP_relayid_ed, KP_relaysign_ed)


# # https://gitlab.torproject.org/tpo/core/tor/-/raw/main/src/app/config/fallback_dirs.inc?ref_type=heads
# # https://spec.torproject.org/dir-list-spec.html
# # these don't even work
# import re

# with open("tor_fallback_dirs.inc") as f:
#   data = f.read()

# entries = data.split('\n\n')[1].split('\n,\n')[:-1]

# directory = []
# for entry in entries:
#   entry = entry.split('\n')

#   firstline = r'"(?P<dir_address>\d+\.\d+\.\d+\.\d+(?::\d+)?) +orport=(?P<or_port>\d+) +id=(?P<id>[0-9a-fA-F]+)" *'
#   extrakv = r'" +(?P<key>[a-z_]+)=(?P<value>[^"]+)" *'
#   commentkv = r'/\* +(?P<key>[a-z_]+)=(?P<value>[^"]+) +\*/'

#   a = re.fullmatch(firstline, entry[0]).groupdict()
#   b = {x['key']:x['value'] for x in [x.groupdict() for x in [re.fullmatch(extrakv, x) for x in entry] if x is not None]}
#   c = {x['key']:x['value'] for x in [x.groupdict() for x in [re.fullmatch(commentkv, x) for x in entry] if x is not None]}

#   directory.append({
#     'host': (a['dir_address'], a['or_port']),
#     'fingerprint': a['id'],
#     'name': c['nickname'],
#   })

# #directory.sort(key = lambda x: (int(x['host'][1]), x['name']))
# directory.sort(key = lambda x: x['name'])

# print('Name'.ljust(max(len(d['name']) for d in directory)), 'IP address'.ljust(19), 'Port'.ljust(5), 'Fingerprint')
# for d in directory:
#   print(
#     d['name'].ljust(max(len(d['name']) for d in directory)),
#     '.'.join(c.rjust(3) for c in d['host'][0].split('.')),
#     d['host'][1].rjust(5), d['fingerprint']
#   )





# https://spec.torproject.org/dir-spec/netdoc.html
# (i removed Opt handling (it's not in the consensus i got :))
# NL = The ascii LF character (hex value 0x0a).

import re

# Document ::= (Item | NL)+
def parsedocument(document):
  items = []
  while len(document) > 0:
    while len(document) > 0 and document[0] == '\n':
      document = document[1:]
    if len(document) == 0:
      break
    item,document = parseitem(document)
    items.append(item)
  return items

# Item ::= KeywordLine Object?
def parseitem(document):
  keywordline,document = parsekeywordline(document)
  objects,document = parserepeated(parseobject, document)
  return (keywordline, objects), document

# KeywordLine ::= Keyword (WS Argument)* NL
# WS = (SP | TAB)+
# Argument ::= ArgumentChar+
# ArgumentChar ::=  Any unicode characters encoded in UTF-8, excluding NL, NUL, and SP.
def parsekeywordline(document):
  keyword,document = parsebyregex(keywordregex, document)
  arguments,document = parsebyregex(r'([ \t]+[^\0\n \t]+)*[ \t]*\n', document)
  if arguments is None:
    print(repr(document))
  arguments = arguments.split()
  return (keyword, arguments), document

# Object ::= BeginLine Base64-encoded-data EndLine
# BeginLine ::= "-----BEGIN " Keyword (" " Keyword)*"-----" NL
# EndLine ::= "-----END " Keyword (" " Keyword)* "-----" NL
def parseobject(document):
  beginline,document = parsebyregex(r'-----BEGIN( ' + keywordregex + r')+-----\n', document)
  if beginline is None:
    return None, document
  keyword = beginline[11:-6] # cut out "-----BEGIN " and "-----\n"
  data = ''
  while not document.startswith('-'):
    line,document = document.split('\n', maxsplit = 1)
    data += line
  assert document.startswith('-----END ' + keyword + '-----\n')
  endline,document = document.split('\n', maxsplit = 1)
  return (keyword, data), document

# Keyword = KeywordStart KeywordChar*
# KeywordStart ::= 'A' ... 'Z' | 'a' ... 'z' | '0' ... '9'
# KeywordChar ::= KeywordStart | '-'
keywordregex = r'[A-Za-z0-9][A-Za-z0-9-]*'

def parsebyregex(pattern, document):
  m = re.match(pattern, document)
  if m is None:
    return None, document
  return document[:m.end()], document[m.end():]

def parserepeated(p, document):
  xs = []
  while True:
    x,document = p(document)
    if x is None:
      break
    xs.append(x)
  return xs, document






def parseconsensus(consensus):
  (nsv,vs),consensus = splitat(2, consensus)
  assert nsv == (('network-status-version', ['3']), [])
  assert vs[0][0] == 'vote-status'
  assert vs[1] == []
  votestatustype = vs[0][1]
  print("consensus document of type:", votestatustype)

  while consensus[0][0][0] != 'valid-after':
    _,consensus = splitat(1, consensus)
  (v,),consensus = splitat(1, consensus)
  assert v[1] == []
  validafter = ' '.join(v[0][1])

  while consensus[0][0][0] != 'known-flags':
    _,consensus = splitat(1, consensus)
  (fs,),consensus = splitat(1, consensus)
  assert fs[1] == []
  knownflags = fs[0][1]

  while consensus[0][0][0] != 'params':
    _,consensus = splitat(1, consensus)
  (ps,),consensus = splitat(1, consensus)
  assert ps[1] == []
  parameters = ps[0][1]

  while consensus[0][0][0] != 'shared-rand-previous-value':
    _,consensus = splitat(1, consensus)
  (s1,),consensus = splitat(1, consensus)
  assert s1[1] == []
  srv1 = s1[0][1][1]

  while consensus[0][0][0] != 'shared-rand-current-value':
    _,consensus = splitat(1, consensus)
  (s2,),consensus = splitat(1, consensus)
  assert s2[1] == []
  srv2 = s2[0][1][1]

  while consensus[0][0][0] != 'dir-source':
    _,consensus = splitat(1, consensus)
  authorities,consensus = parserepeated(parseauthority, consensus)

  routers,consensus = parserepeated(parserouter, consensus)

  _,consensus = parseconsensuslinenoobject('directory-footer', consensus)
  _,consensus = parseconsensuslinenoobject('bandwidth-weights', consensus) # ignored
  signatures,consensus = parserepeated(c(parseconsensuslinewithobject)('directory-signature'), consensus) # ignored - i'm not reading allat
  assert consensus == []
  return (knownflags, parameters, authorities, routers, srv1, srv2, validafter)

def parseauthority(consensus):
  if consensus[0][0][0] != 'dir-source':
    return None, consensus
  (ds,c,vd),consensus = splitat(3, consensus)
  assert c[0][0] == 'contact'
  assert c[1] == []
  assert vd[0][0] == 'vote-digest'
  assert vd[1] == []
  dirsource = ds[0][1]
  contact = ' '.join(c[0][1])
  votedigest = vd[0][1]
  return (dirsource, contact, votedigest), consensus

def parserouter(consensus):
  r,consensus = parseconsensuslinenoobject('r', consensus)
  if r is None:
    return None, consensus
  name,identity,digest,p1,p2,ip,orport,dirport = r # p1 and p2 are Publication, dirport is directory cache - ignore them
  _,consensus = parserepeated(c(parseconsensuslinenoobject)('a'), consensus) # ips ignored (i'm not using ipv6)
  flags,consensus = parseconsensuslinenoobject('s', consensus) # https://spec.torproject.org/dir-spec/consensus-formats.html#item:s
  _,consensus = parseconsensuslinenoobject('v', consensus) # version ignored - i don't really care
  # https://spec.torproject.org/dir-spec/consensus-formats.html#vote-and-consensus-document-items-in-ad-hoc-representation-continued-2
  _,consensus = parseconsensuslinenoobject('pr', consensus) # proto ignored - i don't care (actually what is this)
  _,consensus = parseconsensuslinenoobject('w', consensus) # bandwidth ignored - i don't really care
  exitports,consensus = parseconsensuslinenoobject('p', consensus)
  return (name, identity, digest, ip, orport, flags, exitports), consensus

def parseconsensuslinenoobject(kw, consensus):
  if len(consensus) == 0 or consensus[0][0][0] != kw:
    return None, consensus
  (l,),consensus = splitat(1, consensus)
  assert l[1] == []
  return l[0][1], consensus

def parseconsensuslinewithobject(kw, consensus):
  if len(consensus) == 0 or consensus[0][0][0] != kw:
    return None, consensus
  (l,),consensus = splitat(1, consensus)
  return (l[0][1], l[1]), consensus

# currying
def c(f):
  def f1(x):
    def f2(y):
      return f(x, y)
    return f2
  return f1



# The “ntor” handshake

# This handshake uses a set of DH handshakes to compute a set
# of shared keys which the client knows are shared only with
# a particular server, and the server knows are shared with
# whomever sent the original handshake (or with nobody at all).
# Here we use the “curve25519” group and representation as specified
# in “Curve25519: new Diffie-Hellman speed records” by D. J. Bernstein.

# [The ntor handshake was added in Tor 0.2.4.8-alpha.]

# In this section, define:

# H(x,t) as HMAC_SHA256 with message x and key t.
# H_LENGTH  = 32
# ID_LENGTH = 20
# G_LENGTH  = 32
# PROTOID   = "ntor-curve25519-sha256-1"
# t_mac     = PROTOID | ":mac"
# t_key     = PROTOID | ":key_extract"
# t_verify  = PROTOID | ":verify"
# G         = The preferred base point for curve25519 ([9])
# KEYGEN()  = The curve25519 key generation algorithm, returning
#             a private/public keypair.
# m_expand  = PROTOID | ":key_expand"
# KEYID(A)  = A
# EXP(a, b) = The ECDH algorithm for establishing a shared secret.

import hmac

def H(x, t):
  return hmac.new(t, x, hashlib.sha256).digest()

H_LENGTH  = 32
ID_LENGTH = 20
G_LENGTH  = 32
PROTOID   = b"ntor-curve25519-sha256-1"
t_mac     = PROTOID + b":mac"
t_key     = PROTOID + b":key_extract"
t_verify  = PROTOID + b":verify"
m_expand  = PROTOID + b":key_expand"

import secrets
import cryptography.hazmat.primitives.asymmetric.x25519


# For newer KDF needs, including ntor and hs-ntor,
# Tor uses the key derivation function HKDF from RFC5869,
# instantiated with SHA256. (This is due to a construction from Krawczyk.)
# The generated key material is:

# K = K_1 | K_2 | K_3 | ...

#        Where H(x,t) is HMAC_SHA256 with value x and key t
#          and K_1     = H(m_expand | INT8(1) , KEY_SEED )
#          and K_(i+1) = H(K_i | m_expand | INT8(i+1) , KEY_SEED )
#          and m_expand is an arbitrarily chosen value,
#          and INT8(i) is a octet with the value "i".

# In RFC5869’s vocabulary, this is HKDF-SHA256 with info == m_expand,
# salt == t_key (a constant), and IKM == secret_input (the output of the ntor handshake).
# m_expand and t_key are constant parameters, whose values are stated whenever the use of KDF-RFC5869 is specified.

# When partitioning this keystream for the current relay cell encryption protocol from the ntor handshake,
# the first SHA1_LEN bytes form the forward digest Df; the next SHA1_LEN form the backward digest Db;
# the next KEY_LEN form Kf, the next KEY_LEN form Kb, and the final SHA1_LEN bytes are taken as a nonce
# to use in the place of KH in the hidden service protocol. Excess bytes from K are discarded.

def generatekey(seed, length):
  count = ((length - 1) // H_LENGTH) + 1
  k = b''
  ki = b''
  i = 1
  for i in range(1, count + 1):
    ki = H(ki + m_expand + bytes([i]), seed)
    k += ki
  return k[:length]

def getntorkeys(seed):
  k = generatekey(seed, SHA1_LEN + SHA1_LEN + KEY_LEN + KEY_LEN + SHA1_LEN)
  #print('key', k)
  Df,k = splitat(SHA1_LEN, k)
  Db,k = splitat(SHA1_LEN, k)
  Kf,k = splitat(KEY_LEN, k)
  Kb,k = splitat(KEY_LEN, k)
  KH,k = splitat(SHA1_LEN, k)
  return Df, Db, Kf, Kb, KH

# To perform the handshake, the client needs to know NODEID = SHA1(DER(KP_relayid_id)) for the server,
# and an ntor onion key (a curve25519 public key, KP_onion_ntor) for that server.
# Call the ntor onion key B.

# The client generates a temporary keypair:
# x,X = KEYGEN()

# and generates a client-side handshake with contents:
# Field Value Size
# NODEID  Server identity digest  ID_LENGTH bytes
# KEYID KEYID(B)  H_LENGTH bytes
# CLIENT_KP X G_LENGTH bytes

# The server generates a keypair of y,Y = KEYGEN(), and uses its ntor private key b to compute:

# secret_input = EXP(X,y) | EXP(X,b) | ID | B | X | Y | PROTOID
# KEY_SEED = H(secret_input, t_key)
# verify = H(secret_input, t_verify)
# auth_input = verify | ID | B | Y | X | PROTOID | "Server"

# The server’s handshake reply is:
# Field     Value                Size
# SERVER_KP Y                    G_LENGTH bytes
# AUTH      H(auth_input, t_mac) H_LENGTH bytes

# The client then checks Y is in G* [see NOTE below], and computes

# secret_input = EXP(Y,x) | EXP(B,x) | ID | B | X | Y | PROTOID
# KEY_SEED = H(secret_input, t_key)
# verify = H(secret_input, t_verify)
# auth_input = verify | ID | B | Y | X | PROTOID | "Server"

# The client verifies that AUTH == H(auth_input, t_mac).

# Both parties check that none of the EXP() operations produced the point at infinity.
# [NOTE: This is an adequate replacement for checking Y for group membership, if the group is curve25519.]

# Both parties now have a shared value for KEY_SEED. They expand this into the keys
# needed for the Tor relay protocol, using the KDF described in “KDF-RFC5869” and the tag m_expand.

def tocreatecell(cid, nodeid, Bbytes, Xbytes):
  data = nodeid + Bbytes + Xbytes
  return Cell(cid, CREATE2, struct.pack(">HH", 2, len(data)) + data) # 2 for "ntor" handshake

import base64

def createfirsthop(conn, nodeid, ntorkey):
  B = cryptography.hazmat.primitives.asymmetric.x25519.X25519PublicKey.from_public_bytes(base64.b64decode(ntorkey + '=='))
  Bbytes = B.public_bytes_raw()

  x = cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey.generate()
  X = x.public_key()
  Xbytes = X.public_bytes_raw()

  cid = 0x81818181 | secrets.randbits(31)
  conn.send(tocreatecell(cid, nodeid, Bbytes, Xbytes))

  c = conn.recv()
  assert c.command == CREATED2

  (l,),rest = unpackstart(">H", c.body)
  data,rest = splitat(l, rest)
  assert len(data) == G_LENGTH + H_LENGTH
  serverkey,auth = splitat(G_LENGTH, data)

  Y = cryptography.hazmat.primitives.asymmetric.x25519.X25519PublicKey.from_public_bytes(serverkey)
  Ybytes = Y.public_bytes_raw()

  secret_input = x.exchange(Y) + x.exchange(B) + nodeid + Bbytes + Xbytes + Ybytes + PROTOID 
  seed = H(secret_input, t_key)
  verify = H(secret_input, t_verify)

  auth_input = verify + nodeid + Bbytes + Ybytes + Xbytes + PROTOID + b"Server"

  assert auth == H(auth_input, t_mac)

  Df,Db,Kf,Kb,KH = getntorkeys(seed)
  return Df, Db, Kf, Kb, cid





# def createcircuithop1(conn):
#   cid = 0x80000000 | secrets.randbits(31)
#   conn.send(tocreate2cell(cid, 2, data))

def getrelaydescriptor(fingerprint):
  if os.path.exists(f"relaydescriptordata.{fingerprint}.pkl"):
    with open(f"relaydescriptordata.{fingerprint}.pkl", "rb") as f:
      descriptor = pickle.load(f)
    print(f"got processed relay {fingerprint} descriptor from cached file")
  else:
    if os.path.exists(f"relaydescriptor.{fingerprint}.pkl"):
      with open(f"relaydescriptor.{fingerprint}.pkl", "rb") as f:
        descriptor = pickle.load(f)
      print(f"got parsed relay {fingerprint} descriptor from cached file")
    else:
      if os.path.exists(f"relaydescriptor.{fingerprint}.txt"):
        with open(f"relaydescriptor.{fingerprint}.txt") as f:
          descriptor = f.read()
        print(f"got relay {fingerprint} descriptor from cached file")
      else:
        d = random.choice(directory)
        descriptor = requests.get(f"http://{d['host'][0]}:{d['host'][1]}/tor/server/fp/{fingerprint}.z").text
        with open(f"relaydescriptor.{fingerprint}.txt", "w") as f:
          f.write(descriptor)
        print(f"got relay {fingerprint} descriptor from {d['host'][0]}:{d['host'][1]}")

      descriptor = parsedocument(descriptor)
      with open(f"relaydescriptor.{fingerprint}.pkl", "wb") as f:
        pickle.dump(descriptor, f, 0)
      print(f"parsed relay {fingerprint} descriptor from netdoc")

    # descriptor = parsedescriptor(descriptor)
    # with open(f"relaydescriptordata.{fingerprint}.pkl", "wb") as f:
    #   pickle.dump(descriptor, f, 0)
    # print(f"processed relay {fingerprint} descriptor")

  return descriptor

# Calculating the ‘Digest’ field

# The ‘Digest’ field itself serves the purpose to check if a cell has been fully decrypted,
# that is, all onion layers have been removed. Having a single field, namely ‘Recognized’,
# is not sufficient, as outlined above.

# In this section, we assume an incrementally updated hash function,
# where hash_calculate(state) computes the current digest, and
# hash_update(state,M) adjusts the hash function’s state by adding M to its input.
# For ordinary circuits, the hash function used here is SHA-1.
# For onion service circuits, the hash function is SHA3-256.

# When ENCRYPTING a relay cell, an implementation does the following:

# # Encode the cell in binary (recognized and digest set to zero)
# tmp = cmd + [0, 0] + stream_id + [0, 0, 0, 0] + length + data + padding

# # Update the hash state with the encoded data
# hash_state = hash_update(hash_state, tmp)
# digest = hash_calculate(hash_state)

# # The encoded data is the same as above with the digest field not being
# # zero anymore
# encoded = cmd + [0, 0] + stream_id + digest[0..4] + length + data +
#           padding

# # Now we can encrypt the cell by adding the onion layers ...

# When DECRYPTING a relay cell, an implementation does the following:

# decrypted = decrypt(cell)

# # Replace the digest field in decrypted by zeros
# tmp = decrypted[0..5] + [0, 0, 0, 0] + decrypted[9..]

# # Update the digest field with the decrypted data and its digest field
# # set to zero
# hash_state = hash_update(hash_state, tmp)
# digest = hash_calculate(hash_state)

# if digest[0..4] == decrypted[5..9]
#   # The cell has been fully decrypted ...

# The caveat itself is that only the binary data with the digest bytes set to zero
# are being taken into account when calculating the running digest.
# The final plain-text cells (with the digest field set to its actual value) are not taken into the running digest.

# For a stream cipher, unless otherwise specified,
# we use 128-bit AES in counter mode,
# with an IV of all 0 bytes. (We also require AES256.)
# (stream cipher is 128 bit AES - counter mode - IV all 0s - AES256? - rbcavi)

import Cryptodome.Cipher.AES

class RelayState:
  def __init__(self, Df, Db, Kf, Kb):
    #print(Df, Db, Kf, Kb)
    self.fdigest = hashlib.sha1(Df)
    self.bdigest = hashlib.sha1(Db)
    self.fcipher = Cryptodome.Cipher.AES.new(Kf, Cryptodome.Cipher.AES.MODE_CTR, nonce = b'\0' * 8)
    self.bcipher = Cryptodome.Cipher.AES.new(Kb, Cryptodome.Cipher.AES.MODE_CTR, nonce = b'\0' * 8)

  def updatedigest(self, cell):
    assert cell.command == RELAY or cell.command == RELAY_EARLY, f"command {cell.command}????"
    # assume the recognized and digest fields are both 0
    self.fdigest.update(cell.body)
    cell.body = cell.body[0:5] + self.fdigest.digest()[:4] + cell.body[9:]

  def checkselfdigest(self, cell):
    # for recieved and decrypted cells
    # return whether the cell came from this relay
    assert cell.command == RELAY or cell.command == RELAY_EARLY, f"command {cell.command}????"
    if cell.body[1:3] != b'\0\0': # nope (quickfail)
      return False
    tempbody = cell.body[0:5] + b'\0\0\0\0' + cell.body[9:]
    tempbdigest = self.bdigest.copy()
    tempbdigest.update(tempbody)
    if tempbdigest.digest()[:4] != cell.body[5:9]:
      return False
    self.bdigest = tempbdigest
    return True

  def encrypt(self, cell):
    return Cell(cell.circuitid, cell.command, self.fcipher.encrypt(cell.body))

  def decrypt(self, cell):
    return Cell(cell.circuitid, cell.command, self.bcipher.decrypt(cell.body))



# The body of an EXTEND2 message contains:
# Field        Description               Size
# NSPEC        Number of link specifiers 1 byte
# NSPEC times:
#   LSTYPE     Link specifier type       1 byte
#   LSLEN      Link specifier length     1 byte
#   LSPEC      Link specifier            LSLEN bytes
# HTYPE        Client Handshake Type     2 bytes
# HLEN         Client Handshake Data Len 2 bytes
# HDATA        Client Handshake Data     HLEN bytes

# an EXTEND2 cell is constructed from a CREATE2 cell
# only takes ipv4 addresses
# pretty sure the circuit id is not used (an EXTEND2 cell is always in a RELAY cell)
def toextendcell(createcell, addr, port, nodeid):
  addr = [int(c) for c in addr.split('.')]
  return Cell(createcell.circuitid, RELAY_EXTEND2, struct.pack(">BBBBBBBHBB20s", 2, 0, 6, addr[0], addr[1], addr[2], addr[3], port, 2, 20, nodeid) + createcell.body)



# The body of each unencrypted relay cell consists of an enveloped relay message, encoded as follows:
# Field         Size
# Relay command 1 byte
# Recognized    2 bytes
# StreamID      2 bytes
# Digest        4 bytes
# Length        2 bytes
# Data          Length bytes
# Padding       CELL_BODY_LEN - 11 - Length bytes

# The relay commands are:
# Command Identifier             Type    Description
# Core protocol
# 1       BEGIN                  F       Open a stream
# 2       DATA                   F/B     Transmit data
# 3       END                    F/B     Close a stream
# 4       CONNECTED              B       Stream has successfully opened
# 5       SENDME                 F/B, C? Acknowledge traffic
# 6       EXTEND                 F, C    Extend a circuit with TAP (obsolete)
# 7       EXTENDED               B, C    Finish extending a circuit with TAP (obsolete)
# 8       TRUNCATE               F, C    Remove nodes from a circuit (unused)
# 9       TRUNCATED              B, C    Report circuit truncation (unused)
# 10      DROP                   F/B, C  Long-range padding
# 11      RESOLVE                F       Hostname lookup
# 12      RESOLVED               B       Hostname lookup reply
# 13      BEGIN_DIR              F       Open stream to directory cache
# 14      EXTEND2                F, C    Extend a circuit
# 15      EXTENDED2              B, C    Finish extending a circuit
# 16..18  Reserved                       For UDP; see prop339.
# Conflux
# 19      CONFLUX_LINK           F, C    Link circuits into a bundle
# 20      CONFLUX_LINKED         B, C    Acknowledge link request
# 21      CONFLUX_LINKED_ACK     F, C    Acknowledge CONFLUX_LINKED message (for timing)
# 22      CONFLUX_SWITCH         F/B, C  Switch between circuits in a bundle
# Onion services
# 32      ESTABLISH_INTRO        F, C    Create introduction point
# 33      ESTABLISH_RENDEZVOUS   F, C    Create rendezvous point
# 34      INTRODUCE1             F, C    Introduction request (to intro point)
# 35      INTRODUCE2             B, C    Introduction request (to service)
# 36      RENDEZVOUS1            F, C    Rendezvous request (to rendezvous point)
# 37      RENDEZVOUS2            B, C    Rendezvous request (to client)
# 38      INTRO_ESTABLISHED      B, C    Acknowledge ESTABLISH_INTRO
# 39      RENDEZVOUS_ESTABLISHED B, C    Acknowledge ESTABLISH_RENDEZVOUS
# 40      INTRODUCE_ACK          B, C    Acknowledge INTRODUCE1
# Circuit padding
# 41      PADDING_NEGOTIATE      F, C    Negotiate circuit padding
# 42      PADDING_NEGOTIATED     B, C    Negotiate circuit padding
# Flow control
# 43      XON                    F/B     Stream-level flow control
# 44      XOFF                   F/B     Stream-level flow control


# Core protocol
RELAY_BEGIN                  = 1  # Open a stream
RELAY_DATA                   = 2  # Transmit data
RELAY_END                    = 3  # Close a stream
RELAY_CONNECTED              = 4  # Stream has successfully opened
RELAY_SENDME                 = 5  # Acknowledge traffic
RELAY_EXTEND                 = 6  # Extend a circuit with TAP (obsolete)
RELAY_EXTENDED               = 7  # Finish extending a circuit with TAP (obsolete)
RELAY_TRUNCATE               = 8  # Remove nodes from a circuit (unused)
RELAY_TRUNCATED              = 9  # Report circuit truncation (unused)
RELAY_DROP                   = 10 # Long-range padding
RELAY_RESOLVE                = 11 # Hostname lookup
RELAY_RESOLVED               = 12 # Hostname lookup reply
RELAY_BEGIN_DIR              = 13 # Open stream to directory cache
RELAY_EXTEND2                = 14 # Extend a circuit
RELAY_EXTENDED2              = 15 # Finish extending a circuit
# Conflux
RELAY_CONFLUX_LINK           = 19 # Link circuits into a bundle
RELAY_CONFLUX_LINKED         = 20 # Acknowledge link request
RELAY_CONFLUX_LINKED_ACK     = 21 # Acknowledge CONFLUX_LINKED message (for timing)
RELAY_CONFLUX_SWITCH         = 22 # Switch between circuits in a bundle
# Onion services
RELAY_ESTABLISH_INTRO        = 32 # Create introduction point
RELAY_ESTABLISH_RENDEZVOUS   = 33 # Create rendezvous point
RELAY_INTRODUCE1             = 34 # Introduction request (to intro point)
RELAY_INTRODUCE2             = 35 # Introduction request (to service)
RELAY_RENDEZVOUS1            = 36 # Rendezvous request (to rendezvous point)
RELAY_RENDEZVOUS2            = 37 # Rendezvous request (to client)
RELAY_INTRO_ESTABLISHED      = 38 # Acknowledge ESTABLISH_INTRO
RELAY_RENDEZVOUS_ESTABLISHED = 39 # Acknowledge ESTABLISH_RENDEZVOUS
RELAY_INTRODUCE_ACK          = 40 # Acknowledge INTRODUCE1
# Circuit padding
RELAY_PADDING_NEGOTIATE      = 41 # Negotiate circuit padding
RELAY_PADDING_NEGOTIATED     = 42 # Negotiate circuit padding
# Flow control
RELAY_XON                    = 43 # Stream-level flow control
RELAY_XOFF                   = 44 # Stream-level flow control

def torelaycell(ctype, cid, sid, cell):
  padding = b'\0\0\0\0' + secrets.token_bytes(CELL_BODY_LEN - 4 - 11 - len(cell.body))
  return Cell(cid, ctype, struct.pack(">BHHIH", cell.command, 0, sid, 0, len(cell.body)) + cell.body + padding)

def fromrelaycell(cell):
  assert cell.command == RELAY or cell.command == RELAY_EARLY, f"type {cell.command}???"
  (command,recognized,sid,digest,length),rest = unpackstart(">BHHIH", cell.body)
  body,rest = splitat(length, rest)
  assert recognized == 0
  # ignore digest - it's checked somewhere else
  return sid, Cell(cell.circuitid, command, body)

def relaytoend(conn, cell, relays):
  relays[-1].updatedigest(cell)
  #print(cell)
  for relay in reversed(relays):
    cell = relay.encrypt(cell)
  #print(cell)
  conn.send(cell)

def relayfrom(cell, relays):
  #print(cell)
  for i,relay in enumerate(relays):
    cell = relay.decrypt(cell)
    if relay.checkselfdigest(cell):
      #print(cell)
      sid,cell = fromrelaycell(cell)
      return i, sid, cell
  assert False # houston,

def relayfromend(cell, relays):
  i,sid,cell = relayfrom(cell, relays)
  assert i == len(relays) - 1
  return sid, cell

def relayfromend(cell, relays):
  #print(cell)
  for i,relay in enumerate(relays):
    cell = relay.decrypt(cell)
    if relay.checkselfdigest(cell):
      #print(cell)
      #print(cell)
      sid,cell = fromrelaycell(cell)
      #print(cell)
      assert i == len(relays) - 1
      return sid, cell
  assert False # houston,

def createnexthop(conn, cid, addr, port, relays, nodeid, ntorkey):
  B = cryptography.hazmat.primitives.asymmetric.x25519.X25519PublicKey.from_public_bytes(base64.b64decode(ntorkey + '=='))
  Bbytes = B.public_bytes_raw()

  x = cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey.generate()
  X = x.public_key()
  Xbytes = X.public_bytes_raw()

  relaytoend(conn, torelaycell(RELAY_EARLY, cid, 0, toextendcell(tocreatecell(cid, nodeid, Bbytes, Xbytes), addr, port, nodeid)), relays)

  sid,extended = relayfromend(conn.recv(), relays)
  assert extended.command == RELAY_EXTENDED2

  (l,),rest = unpackstart(">H", extended.body)
  data,rest = splitat(l, rest)
  assert len(data) == G_LENGTH + H_LENGTH
  serverkey,auth = splitat(G_LENGTH, data)

  Y = cryptography.hazmat.primitives.asymmetric.x25519.X25519PublicKey.from_public_bytes(serverkey)
  Ybytes = Y.public_bytes_raw()

  secret_input = x.exchange(Y) + x.exchange(B) + nodeid + Bbytes + Xbytes + Ybytes + PROTOID 
  seed = H(secret_input, t_key)
  verify = H(secret_input, t_verify)

  auth_input = verify + nodeid + Bbytes + Ybytes + Xbytes + PROTOID + b"Server"

  assert auth == H(auth_input, t_mac)

  Df,Db,Kf,Kb,KH = getntorkeys(seed)
  return Df, Db, Kf, Kb




































































# Hidden services: overview and preliminaries

# Hidden services aim to provide responder anonymity for
# bidirectional stream-based communication on the Tor network.
# Unlike regular Tor connections, where the connection initiator receives anonymity
# but the responder does not, hidden services attempt to provide bidirectional anonymity.

# Participants:

# Operator -- A person running a hidden service
# Host, "Server" -- The Tor software run by the operator to provide a hidden service.
# User -- A person contacting a hidden service.
# Client -- The Tor software running on the User's computer
# Hidden Service Directory (HSDir) -- A Tor node that hosts signed statements
#   from hidden service hosts so that users can make contact with them.
# Introduction Point -- A Tor node that accepts connection requests for hidden services
#   and anonymously relays those requests to the hidden service.
# Rendezvous Point -- A Tor node to which clients and servers connect and which relays traffic between them.

# Improvements over previous versions

# Here is a list of improvements of this proposal over the legacy hidden services:

# a) Better crypto (replaced SHA1/DH/RSA1024 with SHA3/ed25519/curve25519)
# b) Improved directory protocol leaking less to directory servers.
# c) Improved directory protocol with smaller surface for targeted attacks.
# d) Better onion address security against impersonation.
# e) More extensible introduction/rendezvous protocol.
# f) Offline keys for onion services
# g) Restricted discovery mode

# Notation and vocabulary

# Unless specified otherwise, all multi-octet integers are big-endian.

# We write sequences of bytes in two ways:
# 1. A sequence of two-digit hexadecimal values in square brackets,
#    as in [AB AD 1D EA].
# 2. A string of characters enclosed in quotes, as in "Hello". The
#    characters in these strings are encoded in their ascii
#    representations; strings are NOT nul-terminated unless
#    explicitly described as NUL terminated.

#    We use the words "byte" and "octet" interchangeably.

#    We use the vertical bar | to denote concatenation.
# (so basically the same as before - big endian integers and bytes as bracketed hex or quoted characters - rbcavi)

# We use INT_N(val) to denote the network (big-endian) encoding of the unsigned integer “val” in N bytes.
# For example, INT_4(1337) is [00 00 05 39]. Values are truncated like so: val % (2 ^ (N * 8)).
# For example, INT_4(42) is 42 % 4294967296 (32 bit).
# (INT_N means N byte integer as bytes - rbcavi)

# Cryptographic building blocks

# This specification uses the following cryptographic building blocks:
# * A stream cipher STREAM(iv, k) where iv is a nonce of length S_IV_LEN bytes
#   and k is a key of length S_KEY_LEN bytes.
# * A public key signature system SIGN_KEYGEN()->seckey, pubkey; SIGN_SIGN(seckey,msg)->sig;
#   and SIGN_CHECK(pubkey, sig, msg) -> { "OK", "BAD" };
#   where secret keys are of length SIGN_SECKEY_LEN bytes,
#   public keys are of length SIGN_PUBKEY_LEN bytes,
#   and signatures are of length SIGN_SIG_LEN bytes.
#   This signature system must also support key blinding operations as discussed
#   in appendix [KEYBLIND] and in section [SUBCRED]: SIGN_BLIND_SECKEY(seckey, blind)->seckey2
#   and SIGN_BLIND_PUBKEY(pubkey, blind)->pubkey2.
# * A public key agreement system "PK", providing PK_KEYGEN()->seckey, pubkey;
#   PK_VALID(pubkey) -> {"OK", "BAD"}; and PK_HANDSHAKE(seckey, pubkey)->output;
#   where secret keys are of length PK_SECKEY_LEN bytes,
#   public keys are of length PK_PUBKEY_LEN bytes,
#   and the handshake produces outputs of length PK_OUTPUT_LEN bytes.
# * A cryptographic hash function H(d), which must be preimage and collision resistant.
# * A cryptographic message authentication code MAC(key,msg) that produces outputs of length MAC_LEN bytes.
# * A key derivation function KDF(message, n) that outputs n bytes.

# As a first pass, I suggest:
# * Instantiate STREAM with AES256-CTR.
# * Instantiate SIGN with Ed25519 and the blinding protocol in [KEYBLIND].
# * Instantiate PK with Curve25519.
# * Instantiate our hash H(d) function with SHA3-256.
# * Instantiate KDF with SHAKE256. We define SHAKE256_KDF(message,n) as SHAKE256(message, n*8).
#   (The SHAKE256 spec defines SHAKE's output length in bits, but in the Tor Specifications we generally state lengths in bytes.)
# * Instantiate MAC(key=k, message=m) with SHA3_256(k_len | k | m), where k_len is htonll(len(k)).

# When we need a particular MAC key length below, we choose MAC_KEY_LEN=32 (256 bits).

# For legacy purposes, we specify compatibility with older versions of
# the Tor introduction point and rendezvous point protocols.
# These used RSA1024, DH1024, AES128, and SHA1, as discussed in rend-spec.txt.

# As in [proposal 220], all signatures are generated not over strings themselves,
# but over those strings prefixed with a distinguishing value.

# Protocol building blocks

# In sections below, we need to transmit the locations and identities of Tor nodes.
# We do so in the link identification format used by EXTEND2 messages in the Tor protocol.

# NSPEC      (Number of link specifiers)   [1 byte]
# NSPEC times:
#   LSTYPE (Link specifier type)           [1 byte]
#   LSLEN  (Link specifier length)         [1 byte]
#   LSPEC  (Link specifier)                [LSLEN bytes]

# Link specifier types are as described in tor-spec.txt. Every set of link specifiers
# SHOULD include at minimum specifiers of type [00] (TLS-over-TCP, IPv4),
# [02] (legacy node identity) and [03] (ed25519 identity key).
# Sets of link specifiers without these three types SHOULD be rejected.

# As of 0.4.1.1-alpha, Tor includes both IPv4 and IPv6 link specifiers
# in v3 onion service protocol link specifier lists. All available addresses SHOULD
# be included as link specifiers, regardless of the address that Tor actually used to connect/extend to the remote relay.

# We also incorporate Tor’s circuit extension handshakes, as used in the CREATE2 and CREATED2
# cells described in tor-spec.txt. In these handshakes, a client who knows a public key
# for a server sends a message and receives a message from that server. Once the exchange is done,
# the two parties have a shared set of forward-secure key material, and the client knows that
# nobody else shares that key material unless they control the secret key corresponding to the server’s public key.

# Assigned relay message types

# These relay message types are reserved for use in the hidden service protocol.

# 32 -- RELAY_COMMAND_ESTABLISH_INTRO
#   Sent from hidden service host to introduction point; establishes introduction point. Discussed in [REG_INTRO_POINT].

# 33 -- RELAY_COMMAND_ESTABLISH_RENDEZVOUS
#   Sent from client to rendezvous point; creates rendezvous point. Discussed in [EST_REND_POINT].

# 34 -- RELAY_COMMAND_INTRODUCE1
#   Sent from client to introduction point; requests introduction. Discussed in [SEND_INTRO1]

# 35 -- RELAY_COMMAND_INTRODUCE2
#   Sent from introduction point to hidden service host; requests introduction. Same format as INTRODUCE1. Discussed in [FMT_INTRO1] and [PROCESS_INTRO2]

# 36 -- RELAY_COMMAND_RENDEZVOUS1
#   Sent from hidden service host to rendezvous point; attempts to join host's circuit to client's circuit. Discussed in [JOIN_REND]

# 37 -- RELAY_COMMAND_RENDEZVOUS2
#   Sent from rendezvous point to client; reports join of host's circuit to client's circuit. Discussed in [JOIN_REND]

# 38 -- RELAY_COMMAND_INTRO_ESTABLISHED
#   Sent from introduction point to hidden service host; reports status of attempt to establish introduction point. Discussed in [INTRO_ESTABLISHED]

# 39 -- RELAY_COMMAND_RENDEZVOUS_ESTABLISHED
#   Sent from rendezvous point to client; acknowledges receipt of ESTABLISH_RENDEZVOUS message. Discussed in [EST_REND_POINT]

# 40 -- RELAY_COMMAND_INTRODUCE_ACK
#   Sent from introduction point to client; acknowledges receipt of INTRODUCE1 message and reports success/failure. Discussed in [INTRO_ACK]

































































def buildcircuit(routers):
  firstrouter = routers[0]

  relaystates = []

  (conn, KP_relayid_ed, KP_relaysign_ed) = connect(firstrouter[3], int(firstrouter[4]))

  fingerprintbytes = base64.b64decode(firstrouter[1] + '==')
  ntorkey = [line for line in getrelaydescriptor(fingerprintbytes.hex()) if line[0][0] == 'ntor-onion-key'][0][0][1][0]
  Df1,Db1,Kf1,Kb1,cid = createfirsthop(conn, fingerprintbytes, ntorkey)
  relaystates.append(RelayState(Df1, Db1, Kf1, Kb1))

  for router in routers[1:]:
    fingerprintbytes = base64.b64decode(router[1] + '==')
    ntorkey = [line for line in getrelaydescriptor(fingerprintbytes.hex()) if line[0][0] == 'ntor-onion-key'][0][0][1][0]
    Df,Db,Kf,Kb = createnexthop(conn, cid, router[3], int(router[4]), relaystates, fingerprintbytes, ntorkey)
    relaystates.append(RelayState(Df, Db, Kf, Kb))

  print("constructed circuit")

  return conn, cid, relaystates















with open("tor-authorities.txt") as f:
  data = f.read()

directory = [{
  'host': (ip, port),
  'fingerprint': fingerprint,
  'name': name,
} for line in data.split('\n') for name,ip,port,fingerprint in [line.split()]]

import random
import requests
import os
import pickle

if os.path.exists("consensusdata.pkl"):
  with open("consensusdata.pkl", "rb") as f:
    consensus = pickle.load(f)
  print("got processed consensus document from cached file")
else:
  if os.path.exists("consensus.pkl"):
    with open("consensus.pkl", "rb") as f:
      consensus = pickle.load(f)
    print("got parsed consensus document from cached file")
  else:
    if os.path.exists("consensus.txt"):
      with open("consensus.txt") as f:
        consensus = f.read()
      print("got consensus document from cached file")
    else:
      d = random.choice(directory)
      consensus = requests.get(f"http://{d['host'][0]}:{d['host'][1]}/tor/status-vote/current/consensus.z").text
      with open("consensus.txt", "w") as f:
        f.write(consensus)
      print(f"got consensus document from {d['host'][0]}:{d['host'][1]}")

    consensus = parsedocument(consensus)
    with open("consensus.pkl", "wb") as f:
      pickle.dump(consensus, f, 0)
    print("parsed consensus document from netdoc")

  consensus = parseconsensus(consensus)
  with open("consensusdata.pkl", "wb") as f:
    pickle.dump(consensus, f, 0)
  print("processed consensus document")











# i now presumably have a working circuit

# i want to test downloading a big file (~1MB)
# but i can't find one :(

# #relaytoend(conn, torelaycell(RELAY, cid, sid, Cell(0, RELAY_BEGIN, b'52.54.161.49:80\0')), relays)
# #relaytoend(conn, torelaycell(RELAY, cid, sid, Cell(0, RELAY_BEGIN, b'199.58.81.140:80\0')), relays)
# relaytoend(conn, torelaycell(RELAY, cid, sid, Cell(0, RELAY_BEGIN, b'208.80.154.240:80\0')), relays)

# sid,connected = relayfromend(conn.recv(), relays)
# assert connected.command == RELAY_CONNECTED, f"type {connected.command}???"
# print(connected)
# print(struct.unpack(">BBBBI", connected.body))

# #relaytoend(conn, torelaycell(RELAY, cid, sid, Cell(0, RELAY_DATA, b'GET / HTTP/1.1\nHost: httpbin.org\n\n\n')), relays)
# #relaytoend(conn, torelaycell(RELAY, cid, sid, Cell(0, RELAY_DATA, b'GET /tor/status-vote/current/consensus.z HTTP/1.1\nHost: 199.58.81.140:80\n\n\n')), relays)
# relaytoend(conn, torelaycell(RELAY, cid, sid, Cell(0, RELAY_DATA, b'GET /wikipedia/commons/4/4a/Naaldvaren_%28Polystichum_setiferum_%27Herrenhausen%27%29_10-04-2024_%28d.j.b.%29.jpg HTTP/1.1\nHost: upload.wikimedia.org\n\n\n')), relays)

# f = open("torout", "wb")
# while True:
#   cell = conn.recv()
#   if cell is None:
#     print('done...')
#     break
#   sid,data = relayfromend(cell, relays)
#   assert data.command == RELAY_DATA
#   print(f.write(data.body))

# relaytoend(conn, torelaycell(RELAY, cid, sid, Cell(0, RELAY_RESOLVE, b'httpbin.org\0')), relays)
# sid,resolved = relayfromend(conn.recv(), relays)
# assert resolved.command == RELAY_RESOLVED, f"type {resolved.command}???"

# def readresolvedentry(data):
#   odata = data
#   if len(data) < 2:
#     return None, odata
#   (rtype,rlength),data = unpackstart(">BB", data)
#   if len(data) < rlength:
#     return None, odata
#   rdata,data = splitat(rlength, data)
#   if len(data) < 4:
#     return None, odata
#   (ttl,),data = unpackstart(">I", data)
#   if rtype == 0x00:
#     rdata = rdata[:-1].decode('utf-8')
#   if rtype == 0x04:
#     assert len(rdata) == 4
#     rdata = [*rdata]
#   if rtype == 0x06:
#     assert len(rdata) == 16
#     rdata = [*rdata]
#   if rtype == 0xf0:
#     rdata = rdata
#   if rtype == 0xf1:
#     rdata = rdata
#   return (rtype, rlength, rdata, ttl), data

# print(parserepeated(readresolvedentry, resolved.body))


# needs an onion address

onion = 'gi3bsuc5ci2dr4xbh5b3kja5c6p5zk226ymgszzx7ngmjpc25tmnhaqd.onion' # xe iaso
#onion = 'xa4r2iadxm55fbnqgwwi5mymqdcofiu3w6rpbtqn7b2dyn7mgwj64jyd.onion'



# The onion address of a hidden service includes its identity public key,
# a version field and a basic checksum. All this information is then base32 encoded as shown below:

# onion_address = base32(PUBKEY | CHECKSUM | VERSION) + ".onion"
# CHECKSUM = SHA3_256(".onion checksum" | PUBKEY | VERSION)[:2]

# where:
# PUBKEY is the 32 bytes ed25519 master pubkey (KP_hs_id) of the hidden service.
# VERSION is a one byte version field (default value '\x03')
# ".onion checksum" is a constant string
# CHECKSUM is truncated to two bytes before inserting it in onion_address

# Here are a few example addresses:
# pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion
# sp3k262uwy4r2k3ycr5awluarykdpag6a7y33jxop4cs2lu5uz5sseqd.onion
# xa4r2iadxm55fbnqgwwi5mymqdcofiu3w6rpbtqn7b2dyn7mgwj64jyd.onion

def getkeyfromonion(onion):
  assert len(onion) == 56 + 6 # data + ".onion"

  oniondata = base64.b32decode(onion[:-6], casefold = True)

  onionkey,checksum,version = struct.unpack(">32s2sB", oniondata)

  assert checksum == SHA3_256(b'.onion checksum' + onionkey + struct.pack(">B", version))[:2]
  assert version == 3

  return onionkey

onionkey = getkeyfromonion(onion)

print('onion key', onionkey, len(onionkey))







# To derive the key for a nonce N and an optional secret s, compute the blinding factor like this:
#   h = SHA3_256(BLIND_STRING | A | s | B | N)
#   BLIND_STRING = "Derive temporary signing key" | INT_1(0)
#   N = "key-blind" | INT_8(period-number) | INT_8(period_length)
#   B = "(1511[...]2202, 4631[...]5960)"

# then clamp the blinding factor 'h' according to the ed25519 spec:
#   h[0] &= 248;
#   h[31] &= 63;
#   h[31] |= 64;

# and do the key derivation as follows:

# private key for the period:
#   a' = h a mod l
#   RH' = SHA-512(RH_BLIND_STRING | RH)[:32]
#   RH_BLIND_STRING = "Derive temporary signing key hash input"
# public key for the period:
#   A' = h A = (ha)B

# Generating a signature of M: given a deterministic random-looking r (see EdDSA paper), take R=rB, S=r+hash(R,A’,M)ah mod l. Send signature (R,S) and public key A’.

# Verifying the signature: Check whether SB = R+hash(R,A’,M)A’.

# (If the signature is valid,
#      SB = (r + hash(R,A',M)ah)B
#         = rB + (hash(R,A',M)ah)B
#         = R + hash(R,A',M)A' )

# This boils down to regular Ed25519 with key pair (a', A').

# See [KEYBLIND-REFS] for an extensive discussion on this scheme and possible alternatives. Also, see [KEYBLIND-PROOF] for a security proof of this scheme.


def getblindkey(pubkey, period, periodlength):
  A = pubkey
  B = ( # ed25519 base point - big endian - x first
    b'\x21\x69\x36\xd3\xcd\x6e\x53\xfe\xc0\xa4\xe2\x31\xfd\xd6\xdc\x5c'
    b'\x69\x2c\xc7\x60\x95\x25\xa7\xb2\xc9\x56\x2d\x60\x8f\x25\xd5\x1a'
    b'\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66'
    b'\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x66\x58'
  )
  N = b'key-blind' + struct.pack('>QQ', period, periodlength)
  BLIND_STRING = b'Derive temporary signing key\0'
  h = bytearray(SHA3_256(BLIND_STRING + A + B + N))
  h[0] &= 248
  h[31] &= 63
  h[31] |= 64
  #h = cryptography.hazmat.primitives.asymmetric.x25519.X25519PrivateKey.from_private_bytes(bytes(h))
  #Ap = h.exchange(A) # i have no idea
  Ap = nacl.bindings.crypto_scalarmult_ed25519_noclamp(bytes(h), A) # i guess?
  print(nacl.bindings.crypto_scalarmult_ed25519(bytes(h), A))
  print(nacl.bindings.crypto_scalarmult_ed25519_noclamp(bytes(h), A))
  print(nacl.bindings.crypto_scalarmult(bytes(h), A))
  return Ap

def getperiod(currtime, periodlength):
  minutes = (currtime + 1) // 60
  minutes -= 12 * 60 # 30 minute voting interval? * 12
  period = minutes // periodlength
  return int(period)




routers = consensus[3]



import calendar

currtime = calendar.timegm(time.strptime(consensus[6], "%Y-%m-%d %H:%M:%S"))

period, periodlength = getperiod(currtime, 1440), 1440

blindkey = getblindkey(onionkey, period, periodlength)





hsdirs = [r for r in routers if 'HSDir' in r[5]]

print(len(hsdirs))

hsdirds = [getrelaydescriptor(base64.b64decode(hsdir[1] + '==').hex()) for i,hsdir in enumerate(hsdirs)]

hsdirds = [(hsdir, hsdird) for hsdir,hsdird in zip(hsdirs, hsdirds) if hsdird != []]

hsdirids = [(hsdir, base64.b64decode([line for line in hsdird if line[0][0] == 'master-key-ed25519'][0][0][1][0] + '==')) for hsdir,hsdird in hsdirds]

srv = base64.b64decode(consensus[4] + '==')

hsidxs = [(SHA3_256(b'node-idx' + hsdirid + srv + struct.pack('>QQ', period, periodlength)), hsdir) for hsdir,hsdirid in hsdirids]

hsstoreidxs = [SHA3_256(b'store-at-idx' + blindkey + struct.pack('>QQQ', i + 1, periodlength, period)) for i in range(2)]

import bisect

hsstoreidxs2 = [bisect.bisect(hsidxs, (hsstoreidx, '')) for hsstoreidx in hsstoreidxs]

print(hsstoreidxs2)

hsstorelocs = [hsidxs[hsstoreidx2:hsstoreidx2 + 3] for hsstoreidx2 in hsstoreidxs2]

print(hsstorelocs)



router = random.choice([r for r in routers if 'Guard' in r[5]])
router2 = random.choice([r for r in routers if r != router and 'HSDir' not in r[5] and 'V2Dir' not in r[5]])
router3 = random.choice([r for r in routers if r != router and r != router2 and 'Exit' in r[5]])
router3 = random.choice([r for r in routers if r != router and r != router2 and 'HSDir' in r[5]])
router3 = random.choice(random.choice(hsstorelocs))[1]

print(router)
print(router2)
print(router3)


conn,cid,relays = buildcircuit([router, router2, router3])



sid = secrets.randbits(16)

print("stream id:", sid)

relaytoend(conn, torelaycell(RELAY, cid, sid, Cell(0, RELAY_BEGIN_DIR, b'')), relays)
sid,resolved = relayfromend(conn.recv(), relays)
print(sid, resolved)


bbb = base64.b64encode(blindkey).decode('utf-8').rstrip('=')

print(bbb)

relaytoend(conn, torelaycell(RELAY, cid, sid, Cell(0, RELAY_DATA, bytes(f'GET /tor/hs/3/{bbb} HTTP/1.1\r\nHost: \r\n\r\n', 'utf-8'))), relays)
#relaytoend(conn, torelaycell(RELAY, cid, sid, Cell(0, RELAY_DATA, bytes(f'GET /tor/status-vote/current/consensus.z HTTP/1.1\r\nHost: \r\n\r\n', 'utf-8'))), relays)
print('a')
sid,resolved = relayfromend(conn.recv(), relays)
print(sid, resolved)