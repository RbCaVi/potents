# moddable roody engine
# three years <3

# [x] grid
#   [x] define
#   [x] draw
# [ ] moving blocks
#   [ ] collapsing blocks
# [ ] welding
# [ ] camera
#   [ ] moving
#   [ ] scaling

import dataclasses
import sys

import pygame

#class Moving(enum.Enum):
#  NONE = enum.auto()

@dataclasses.dataclass
class Block:
  blockid: int

blockids = [
  [0, 1, 2],
  [1, 1, 2],
  [0, 1, 1],
]

blocks = [
  [
    Block(blockid)
    for blockid in row
  ]
  for row in blockids
]

pygame.init()

display = pygame.display.set_mode((640, 480), pygame.RESIZABLE)
clock = pygame.time.Clock()

blocksize = 50

while True:
  for event in pygame.event.get():
    if event.type == pygame.QUIT:
      sys.exit()
  display.fill((255, 255, 255))
  for yi,row in enumerate(blocks):
    for xi,block in enumerate(row):
      x = blocksize * xi
      y = blocksize * yi
      pygame.draw.rect(display, (100 * block.blockid, 128, 128), (x, y, blocksize, blocksize))
  pygame.display.update()
  clock.tick(60)