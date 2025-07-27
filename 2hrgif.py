# from https://www.w3.org/Graphics/GIF/spec-gif89a.txt
# and https://stackoverflow.com/a/28486261
# data blocks is a series of chunks
#   length - u8
#   data - `length` bytes
# and ends with a 0 length chunk
# a gif is made of:
#   header
#     magic - 'GIF'
#     version - '87a' or '89a' (mine does 89a)
#     width, height - u16 * 2
#     flags - byte:
#       has global color table (gct) - 1 bit
#       color resolution - 3 bits - bits in color components-1
#       gct is sorted - 1 bit - idk just put 0
#       log2(gct size)-1 - 3 bits - the size is 2 ^ (@ + 1)
#     background color index - u8 - only applicable if has gct
#     aspect ratio - u8 - 0 for no aspect ratio given - otherwise (@ + 15 / 64)
#   gct (optional) - u8 * 3 * gct size - red green blue for each color
#   sequence of blocks - each one has a one byte identifying code
#     extension - 0x21 - another byte for extension type and then a series of data blocks
#       comment - 0xFE
#         data blocks contain a textual (probably) comment
#       application - 0xFF
#         first block contains
#           application - 8 byte text string
#           authentication code - 3 bytes
#         the rest of the data:
#         code NETSCAPE2.0 is an animated gif (the kind you find on tenor)
#         it has 3 bytes of data after the application code:
#           id - byte - 0x01
#           loop count - u16 - 0 means forever
#       graphic control - 0xF9 - 4 bytes of data
#         flags - byte
#           reserved - 3 bits
#           disposal - 3 bits
#             no disposal specified - 0
#             leave graphic - 1 - don't clear it after drawing
#             restore to background - 2
#             restore to previous - 3
#           needs user input - 1 bit (i'm ignoring this <3)
#           has transparent color - 1 bit
#         delay - u16 - in 1/100 second
#         transparent color index - u8
#       plain text display - 0x01
#         no :)
#     image data - 0x2C
#       left, top, width, height - u16 * 4
#       flags - byte
#         has local color table (lct) - 1 bit
#         is interlaced - 1 bit (no please)
#         lct is sorted - 1 bit - again just put 0 i guess
#         reserved - 2 bits
#         log2(lct size)-1 - 3 bits - the size is 2 ^ (@ + 1)
#       lct (optional) - same as gct
#       image data - as data blocks
#         lzw initial code size - why is this here? - this should (always?) be log2(lct/gct size) - except it has a minimum of 2
#         lzw compressed data of the image - 256 color paletted
#     trailer (end) - 0x3B - ends gif stream - nothing after this
# the lzw compression has variable length codes
# you can read about it on wikipedia (https://en.wikipedia.org/wiki/Lempel%E2%80%93Ziv%E2%80%93Welch) and appendix f of the specification
# it has the first two symbols after the single colors being reset decoder state and end image data (which is a bit redundant)

import struct

# i'm making a specially crafted gif file
# that's 2 hours long (hopefully)
# and 3 mb (hopefully)
# i have no idea what i'm going to put on it
# maybe the declaration of independence in morse code or something

# start with the header

data = b'GIF89a'

# width, height - u16 * 2
# flags - byte:
#   has global color table (gct) - 1 bit
#   color resolution - 3 bits - bits in color components-1
#   gct is sorted - 1 bit - idk just put 0
#   log2(gct size)-1 - 3 bits - the size is 2 ^ (@ + 1)
# background color index - u8 - only applicable if has gct
# aspect ratio - u8 - 0 for no aspect ratio given - otherwise (@ + 15 / 64)

width = 36
height = 36
flags = 0b1_111_0_001 # 8 bit colors - 2 bit unsorted gct (4 colors)
bgcolor = 0 # does this matter if i don't clear to background?
aspect = 0 # no aspect ratio - probably doesn't matter in these modern times
data += struct.pack('<HHBBB', width, height, flags, bgcolor, aspect)

# gct
palette = [
  (0, 0, 0), # black
  (255, 255, 255), # white
  (255, 0, 0), # red
  (0, 255, 255), # eye-blasting blue
]
for r,g,b in palette:
  data += struct.pack('<BBB', r, g, b)

# now an application extension block
# application - 0xFF
#   first block contains
#     application - 8 byte text string
#     authentication code - 3 bytes
#   the rest of the data:
#   code NETSCAPE2.0 is an animated gif (the kind you find on tenor)
#   it has 3 bytes of data after the application code:
#     id - byte - 0x01
#     loop count - u16 - 0 means forever
netscapeapplicationblock = (
  b'\x21\xff' # signature
  b'\x0bNETSCAPE2.0' # 11 byte block - netscape gif idk
  b'\x03\x01\x00\x00' # 3 byte block - id = 1 - loop count = unlimited
  b'\x00' # terminator
)

# graphic control extension block
# graphic control - 0xF9 - 4 bytes of data
#   flags - byte
#     reserved - 3 bits
#     disposal - 3 bits
#       no disposal specified - 0
#       leave graphic - 1 - don't clear it after drawing
#       restore to background - 2
#       restore to previous - 3
#     needs user input - 1 bit (i'm ignoring this <3)
#     has transparent color - 1 bit
#   delay - u16 - in 1/100 second
#   transparent color index - u8

def graphiccontrolblock(delay, transparent = None):
  flags = 0b000_001_0_0 # no transparency - leave graphic
  transp = 0 # no transparency
  if transparent is not None:
    flags |= 1
    transp = transparent

  return (
    b'\x21\xf9' # signature
    b'\x04' + struct.pack('<BHB', flags, delay, transp) + # single block
    b'\x00' # terminator
  ) # 8 bytes

# image data block
# image data - 0x2C
#   left, top, width, height - u16 * 4
#   flags - byte
#     has local color table (lct) - 1 bit
#     is interlaced - 1 bit (no please)
#     lct is sorted - 1 bit - again just put 0 i guess
#     reserved - 2 bits
#     log2(lct size)-1 - 3 bits - the size is 2 ^ (@ + 1)
#   lct (optional) - same as gct
#   image data - as data blocks
#     lzw initial code size - why is this here? - this should (always?) be log2(lct/gct size) - except it has a minimum of 2
#     lzw compressed data of the image - 256 color paletted

def asdatablocks(data):
  out = b''
  while len(data) > 0:
    chunk,data = data[:255], data[255:]
    out += struct.pack('<B', len(chunk)) + chunk
  return out + b'\x00'

def lzwencode(data, symsize):
  # i'm not going to deal with sending a reset code in the middle
  # i'm only going to use this for like 10 pixels anyway
  dictionary = {(i,): i for i in range(2 ** symsize)}
  reset = 2 ** symsize
  end = reset + 1
  nextsym = end + 1
  yield reset
  code = []
  for x in data:
    code.append(x)
    if tuple(code) not in dictionary:
      # i'm assuming code[:-1] is in dictionary
      yield dictionary[tuple(code[:-1])]
      dictionary[tuple(code)] = nextsym
      nextsym += 1
      code = [code[-1]]
  yield dictionary[tuple(code)]
  yield end

def packlzw(symbols, symsize):
  reset = 2 ** (symsize - 1)
  end = reset + 1
  dictsize = end + 1
  osymsize = symsize
  n = 0
  back = 0
  for sym in symbols:
    dictsize += 1
    #print(sym, symsize, bin(n)[2:].rjust(back, '0'), back)
    #print(bin(sym << back)[2:].rjust(back, '0'))
    n |= sym << back
    back += symsize
    #print(sym, symsize, bin(n)[2:].rjust(back, '0'), back)
    while back >= 8:
      byte = n & 255
      n >>= 8
      back -= 8
      yield byte
    # i have no idea what this should be
    # it increments the size when the dictionary overflows
    if dictsize == 2 ** symsize + 1 and symsize < 12: # it is the maximum value
      symsize += 1
    if sym == reset:
      symsize = osymsize
      dictsize = end + 1
    if sym == end:
      #print('end', bin(n)[2:].rjust(back, '0'), back)
      yield n
      break

def imagedatablock(left, top, width, height, imdata):
  flags = 0b0_0_0_00_000 # no lct - no interlacing

  return (
    b'\x2c' # signature
    + struct.pack('<HHHHB', left, top, width, height, flags) +
    b'\x02' # 2 bit lzw starting code size
    + asdatablocks(bytes(packlzw(lzwencode(imdata, 2), 3)))
  )

# a comment extension block <333
# comment - 0xFE
#   data blocks contain a textual (probably) comment

def commentblock(message):
  return (
    b'\x21\xfe' # signature
    + asdatablocks(message) # message
  )

# end
# trailer (end) - 0x3B - ends gif stream - nothing after this

trailerblock = (
  b'\x3b' # terminator
)

data += netscapeapplicationblock

data += commentblock(b'hi guys! i had the great idea to make a 2 hour gif that fits in 3 mb')

pixels = [1] * 36 * 36
for i in range(0, 36, 6):
  pixels[i:i + 36 * 36:36] = [0] * 36
  pixels[i + 5:i + 5 + 36 * 36:36] = [0] * 36
  pixels[i * 36:(i + 1) * 36] = [0] * 36
  pixels[(i + 5) * 36:(i + 6) * 36] = [0] * 36
data += graphiccontrolblock(25)
data += imagedatablock(0, 0, 36, 36, pixels)

data += commentblock(b'there\'s some secret messages for no reason (not yet)')
data += commentblock(b'just to give you something to pass the time for 2 hours while you stare at this gif <3')

# snake

states = [[0 for _ in range(6)] for _ in range(6)]

x = 0
y = 0

message1 = b'ooooo secrets snake idk lorem ipsum dolor sit amet weezer jonathan l booz paddin'
message2 = b'what do you think of my "stegography"? message me on discord (you know who i am)'
message3 = b'what if i told you my darkest secrets to keep the conversation going padding pad'
message4 = b'https://c.tenor.com/UQXtmsgZS68AAAAd/tenor.gif (cupcake.gif <33) adiciscing elit'

def tobits(bs): # assuming the message is all printable
  return [ord(c) - ord('0') for c in ''.join(bin(b)[2:].rjust(7, '0')[::-1] for b in bs)]

bits1 = tobits(message1)
bits2 = tobits(message2)
bits3 = tobits(message3)
bits4 = tobits(message4)

directions = []

for bit1,bit2,bit3,bit4 in zip(bits1, bits2, bits3, bits4):
  directions += [[0, 2][bit1]] * (bit2 + 1)
  directions += [[1, 3][bit3]] * (bit4 + 1)

directions += [0]

dx = [1, 0, -1, 0]
dy = [0, 1, 0, -1]

for direction in directions:
  states[x][y] = {0: 2, 2: 3, 3: 2}[states[x][y]]
  data += graphiccontrolblock(25)
  data += imagedatablock(x * 6 + 1, y * 6 + 1, 4, 4, [states[x][y]] * 16)
  x += dx[direction]
  x %= 6
  y += dy[direction]
  y %= 6

data += commentblock(b'you should probably write some kind of program to decode this tbh frfr')

data += trailerblock

with open('out/hours.gif', 'wb') as f:
  f.write(data)