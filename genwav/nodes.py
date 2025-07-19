import pygame
import sys

pygame.font.init()

font = pygame.font.SysFont('dejavusans', 12)

class Node:
  # a node
  # can have inputs and outputs
  # and sliders? maybe like blender - slider or connection
  # inputs and outputs of types
  
  def __init__(self, pos = (0, 0)):
    self.pos = pos
    self.name = "DEFAULT NODE"
    self.buttons = []
    self.inputs = []
    self.outputs = []
  
  def update(self):
    pass
  
  def size(self):
    return 200, 20
  
  def draw(self):
    display = pygame.surface.Surface(self.size(), pygame.SRCALPHA)
    display.fill((128, 128, 128))
    name = font.render(self.name, True, (0, 0, 0))
    display.blit(name, ((display.get_width() - name.get_width()) / 2, 0))
    return display
  
  def bounds(self):
    return pygame.Rect(self.pos, self.size())
  
  def mousepressed(self, pos):
    # called when the node is clicked on
    # return True means captured by a gui element
    # meaning it's not getting dragged
    return False
  
  def mousedragged(self, rel):
    # only fires if mousepressed() returned True
    # deals with sliders etc
    pass

def addpoint(p1, p2):
  return p1[0] + p2[0], p1[1] + p2[1]

pygame.init()

display = pygame.display.set_mode((640, 480), pygame.RESIZABLE)
clock = pygame.time.Clock()

nodes = [Node(), Node()]

focus = None
focuscaptured = False

while True:
  for event in pygame.event.get():
    if event.type == pygame.QUIT:
      sys.exit()
    if event.type == pygame.MOUSEBUTTONDOWN:
      #print(event)
      if event.button == 1:
        focusi = None
        for i,node in enumerate(nodes):
          if node.bounds().collidepoint(event.pos):
            focusi = i
        #print(focusi)
        if focusi is not None:
          focus = nodes[focusi]
          focuscaptured = focus.mousepressed(event.pos)
        else:
          focus = None
          focuscaptured = False
    if event.type == pygame.MOUSEMOTION:
      if focus is not None:
        if focuscaptured:
          focus.mousedragged(event.rel)
        else:
          #print(focus.pos, event.rel)
          focus.pos = addpoint(focus.pos, event.rel)
    if event.type == pygame.MOUSEBUTTONUP:
      focus = None
      focuscaptured = False
  display.fill((255, 255, 255))
  for node in nodes:
    display.blit(node.draw(), node.pos)
  pygame.display.update()
  clock.tick(60)