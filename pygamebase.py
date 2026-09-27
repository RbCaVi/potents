import pygame
import sys
import math

pygame.init()

display = pygame.display.set_mode((640, 480), pygame.RESIZABLE)
clock = pygame.time.Clock()

while True:
  for event in pygame.event.get():
    if event.type == pygame.QUIT:
      sys.exit()
    if event.type == pygame.MOUSEBUTTONDOWN:
      pass
    if event.type == pygame.MOUSEMOTION:
      pass
    if event.type == pygame.MOUSEBUTTONUP:
      pass
  display.fill((255, 255, 255))
  pygame.display.flip()
  clock.tick(60)