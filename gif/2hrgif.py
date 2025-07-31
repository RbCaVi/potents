import struct
import numpy

from writegif import header, netscapeapplicationblock, commentblock, graphiccontrolblock, imagedatablock, trailerblock

# i'm making a specially crafted gif file
# that's 2 hours long (hopefully)
# and 3 mb (hopefully)
# i have no idea what i'm going to put on it
# maybe the declaration of independence in morse code or something

# start with the header
# and an application extension block
# so you know it's a Netscape Animated Gif Tm

w = 36
h = 36

palette = [
  (0, 0, 0), # black
  (255, 255, 255), # white
  (255, 0, 0), # red
  (0, 255, 255), # eye-blasting blue
]

data = [
  header(w, h, palette),
  netscapeapplicationblock,
  commentblock(b'hi guys! i had the great idea to make a 2 hour gif that fits in 3 mb'),
]

buffer = numpy.full((w, h), -1)

def newframe(frame, delay):
  changed = buffer != frame# & frame != -1
  yi,xi = numpy.nonzero(changed)
  ymin,ymax = min(yi), max(yi)
  xmin,xmax = min(xi), max(xi)
  frame[~changed] = -1
  frame = frame[ymin:ymax + 1, xmin:xmax + 1]
  colors = numpy.unique(frame)
  transp = min(x for x in range(max(colors) + 2) if x not in colors)
  frame[frame == -1] = transp
  return [graphiccontrolblock(delay, transp), imagedatablock(xmin, ymin, xmax - xmin + 1, ymax - ymin + 1, frame.flat)]

pixels = numpy.full((36, 36), 3)
pixels[0:36:6, :] = 0
pixels[5:36:6, :] = 0
pixels[:, 0:36:6] = 0
pixels[:, 5:36:6] = 0

data += newframe(pixels, 25)

data.append(commentblock(b'there\'s some secret messages'))
data.append(commentblock(b'just to give you something to pass the time for 2 hours while you stare at this gif <3'))

# snake

states = [[3 for _ in range(6)] for _ in range(6)]

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
  pixels = numpy.full((36, 36), -1)
  pixels[y * 6 + 1:y * 6 + 5, x * 6 + 1:x * 6 + 5] = states[x][y]
  data += newframe(pixels, 25)
  x += dx[direction]
  x %= 6
  y += dy[direction]
  y %= 6

data.append(commentblock(b'you should probably write some kind of program to decode this tbh frfr'))

data.append(trailerblock)

with open('out/hours.gif', 'wb') as f:
  f.write(b''.join(data))