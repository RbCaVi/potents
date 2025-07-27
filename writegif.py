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

# header and logical screen descriptor
# magic - 'GIF'
# version - '87a' or '89a' (mine does 89a)
# width, height - u16 * 2
# flags - byte:
#   has global color table (gct) - 1 bit
#   color resolution - 3 bits - bits in color components-1
#   gct is sorted - 1 bit - idk just put 0
#   log2(gct size)-1 - 3 bits - the size is 2 ^ (@ + 1)
# background color index - u8 - only applicable if has gct
# aspect ratio - u8 - 0 for no aspect ratio given - otherwise (@ + 15 / 64)

def header(width, height, palette, bgcolor = 0):
  gctsize = max(len(bin(len(palette) - 1)) - 2, 2) # not really any point in having a 2 color palette if the lzw code requires 4 colors
  palette = palette + [(0, 0, 0) for _ in range(len(palette), 2 ** gctsize)]
  
  assert gctsize < 8, f'palette too big: {len(palette)}'
  
  print(gctsize)

  width = width
  height = height
  flags = 0b1_111_0_000 | (gctsize - 1) # 8 bit colors - has unsorted gct
  bgcolor = bgcolor
  aspect = 0 # no aspect ratio - probably doesn't matter in these modern times
  data = b'GIF89a' + struct.pack('<HHBBB', width, height, flags, bgcolor, aspect)

  # gct
  for r,g,b in palette:
    data += struct.pack('<BBB', r, g, b)
  
  return data

# now an application extension block
# extension - 0x21
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
# extension - 0x21
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
  # i'm only going to use this for like 10 pixels anyway right?
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
# extension - 0x21
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