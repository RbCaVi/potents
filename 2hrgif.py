import struct

from writegif import header, netscapeapplicationblock, commentblock, graphiccontrolblock, imagedatablock, trailerblock

# i'm making a specially crafted gif file
# that's 2 hours long (hopefully)
# and 3 mb (hopefully)
# i have no idea what i'm going to put on it
# maybe the declaration of independence in morse code or something

# start with the header
# and an application extension block
# so you know it's a Netscape Animated Gif Tm

palette = [
  (0, 0, 0), # black
  (255, 255, 255), # white
  (255, 0, 0), # red
  (0, 255, 255), # eye-blasting blue
]

data = [
  header(36, 36, palette),
  netscapeapplicationblock,
  commentblock(b'hi guys! i had the great idea to make a 2 hour gif that fits in 3 mb'),
]

pixels = [1] * 36 * 36
for i in range(0, 36, 6):
  pixels[i:i + 36 * 36:36] = [0] * 36
  pixels[i + 5:i + 5 + 36 * 36:36] = [0] * 36
  pixels[i * 36:(i + 1) * 36] = [0] * 36
  pixels[(i + 5) * 36:(i + 6) * 36] = [0] * 36

data.append(graphiccontrolblock(25))
data.append(imagedatablock(0, 0, 36, 36, pixels))

data.append(commentblock(b'there\'s some secret messages for no reason (not yet)'))
data.append(commentblock(b'just to give you something to pass the time for 2 hours while you stare at this gif <3'))

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
  data.append(graphiccontrolblock(25))
  data.append(imagedatablock(x * 6 + 1, y * 6 + 1, 4, 4, [states[x][y]] * 16))
  x += dx[direction]
  x %= 6
  y += dy[direction]
  y %= 6

data.append(commentblock(b'you should probably write some kind of program to decode this tbh frfr'))

data.append(trailerblock)

with open('out/hours.gif', 'wb') as f:
  f.write(b''.join(data))