# moddable roody engine
# three years <3

# [x] grid
#   [x] define
#   [x] draw
# [ ] moving blocks
#   [x] collapsing blocks
#   [ ] multipush
#     [ ] push priority
# [ ] welding
# [ ] camera
#   [ ] moving
#   [ ] scaling
# [ ] entity physics
#   [ ] fast block collision
#     [ ] block collision
# [ ] dynamic block data
#   [x] block types
# [ ] clone roody 2d
#   [ ] force blocks
#     [ ] actuator
#     [ ] magnet
#     [ ] force core
#     [ ] refined core
#   [ ] crafting
#     [ ] oxide
#     [ ] combiner
#     [ ] extractor
#     [ ] furnace

import dataclasses
import sys
import enum
import random

import pygame

@dataclasses.dataclass
class MotionData:
  moving: bool
  dx: int
  dy: int

class Motion(MotionData, enum.Enum):
  NONE = False, 0, 0
  UP = True, 0, -1
  DOWN = True, 0, 1
  LEFT = True, -1, 0
  RIGHT = True, 1, 0

@dataclasses.dataclass
class Block:
  blockid: int
  motion: Motion
  collapsing: bool

blockids = [
  [0, 1, 2, 0, 0, 0, 0, 0],
  [1, 1, 2, 0, 0, 0, 0, 0],
  [0, 1, 1, 0, 0, 0, 0, 0],
  [0, 0, 0, 0, 0, 0, 0, 0],
  [0, 0, 0, 0, 0, 0, 0, 0],
  [0, 0, 0, 0, 0, 0, 0, 0],
]

colors = [
  (  0,   0,   0),
  (  0, 128, 128),
  (100, 128, 128),
  (200, 128, 128),
  (0, 0, 0),
  (0, 0, 0),
]

blocks = [
  [
    Block(blockid, Motion.NONE, False)
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
    if event.type == pygame.MOUSEBUTTONDOWN:
      if event.button == 1:
        x,y = event.pos
        xi,xf = divmod(x, blocksize)
        yi,yf = divmod(y, blocksize)
        if xi < 0 or xi > len(blocks[0]) or yi < 0 or yi > len(blocks):
          continue
        xf /= blocksize
        yf /= blocksize
        xf -= 0.5
        yf -= 0.5
        if abs(xf) < 0.2 and abs(yf) < 0.2:
          blocks[yi][xi].motion = Motion.NONE
        elif abs(xf) > abs(yf):
          if xf > 0:
            blocks[yi][xi].motion = Motion.RIGHT
          else:
            blocks[yi][xi].motion = Motion.LEFT
        else:
          if yf > 0:
            blocks[yi][xi].motion = Motion.DOWN
          else:
            blocks[yi][xi].motion = Motion.UP
    if event.type == pygame.KEYDOWN:
      if event.key == pygame.K_BACKSPACE:
        for row in blocks:
          for block in row:
            block.motion = Motion.NONE
            block.collapsing = False
      if event.key == pygame.K_SPACE:
        for yi,row in enumerate(blocks):
          for xi,block in enumerate(row):
            if block.motion == Motion.NONE:
              continue
            into = blocks[yi + block.motion.dy][xi + block.motion.dx]
            if into.blockid != 0 or into.collapsing:
              block.motion = Motion.NONE
              continue
            into.collapsing = True
        for yi,row in enumerate(blocks):
          for xi,block in enumerate(row):
            blocks[yi][xi] = Block(0, Motion.NONE, False)
            blocks[yi + block.motion.dy][xi + block.motion.dx] = block
            block.motion = Motion.NONE
  display.fill((255, 255, 255))
  for yi,row in enumerate(blocks):
    for xi,block in enumerate(row):
      x = blocksize * xi
      y = blocksize * yi
      pygame.draw.rect(display, colors[block.blockid], (x, y, blocksize, blocksize))
      pygame.draw.rect(display, (255, 255, 255), (x, y, blocksize, blocksize), width = 1)
      pygame.draw.rect(display, (255, 255, 255), (x + blocksize / 2 - 5 + 15 * block.motion.dx, y + blocksize / 2 - 5 + 15 * block.motion.dy, 10, 10))
      if block.collapsing:
        pygame.draw.rect(display, (255, 255, 255), (x + blocksize / 4, y + blocksize / 4, blocksize / 2, blocksize / 2), width = 1)
  pygame.display.update()
  clock.tick(60)