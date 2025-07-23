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

width = 5
height = 5
flags = 0b1_111_0_001 # 8 bit colors - 2 bit unsorted gct (4 colors)
bgcolor = 0 # does this matter if i don't clear to background?
aspect = 0 # no aspect ratio - probably doesn't matter in these modern times
data += struct.pack('<HHBBB', width, height, flags, bgcolor, aspect)

# gct
palette = [
  (0, 0, 0), # black
  (255, 255, 255), # white
  (255, 0, 0), # red
  (0, 255, 0), # green
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
data += (
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

flags = 0b000_001_0_0 # no transparency - leave graphic
delay = 25 # 1/4 second
transp = 0 # no transparency

data += (
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

left = 0
top = 0
width = 1
height = 1
flags = 0b0_0_0_00_000 # no lct - no interlacing

data += (
  b'\x2c' # signature
  + struct.pack('<HHHHB', left, top, width, height, flags) +
  b'\x02' # 2 bit lzw starting code size
  b'\x02\x4c\x01' # "hand encoded" - single white pixel
  b'\x00' # terminator
) # 15 bytes

flags = 0b000_001_0_0 # no transparency - leave graphic
delay = 25 # 1/4 second
transp = 0 # no transparency

data += (
  b'\x21\xf9' # signature
  b'\x04' + struct.pack('<BHB', flags, delay, transp) + # single block
  b'\x00' # terminator
)

left = 0
top = 0
width = 1
height = 1
flags = 0b0_0_0_00_000 # no lct - no interlacing

data += (
  b'\x2c' # signature
  + struct.pack('<HHHHB', left, top, width, height, flags) +
  b'\x02' # 2 bit lzw starting code size
  b'\x02\x54\x01' # "hand encoded" - single red pixel
  b'\x00' # terminator
)

flags = 0b000_001_0_0 # no transparency - leave graphic
delay = 25 # 1/4 second
transp = 0 # no transparency

data += (
  b'\x21\xf9' # signature
  b'\x04' + struct.pack('<BHB', flags, delay, transp) + # single block
  b'\x00' # terminator
)

left = 0
top = 0
width = 1
height = 1
flags = 0b0_0_0_00_000 # no lct - no interlacing

data += (
  b'\x2c' # signature
  + struct.pack('<HHHHB', left, top, width, height, flags) +
  b'\x02' # 2 bit lzw starting code size
  b'\x02\x5c\x01' # "hand encoded" - single green pixel
  b'\x00' # terminator
)

# a comment extension block <333
# comment - 0xFE
#   data blocks contain a textual (probably) comment

message = b'i am the bingus and i made a gif (rbcavi)'

data += (
  b'\x21\xfe' # signature
  + struct.pack('<B', len(message)) + message + # single block
  b'\x00' # terminator
)

# end
# trailer (end) - 0x3B - ends gif stream - nothing after this

data += (
  b'\x3b' # terminator
)

with open('out/bingus.gif', 'wb') as f:
  f.write(data)