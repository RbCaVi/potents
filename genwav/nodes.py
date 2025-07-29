import pygame
import sys

pygame.font.init()

font = pygame.font.SysFont('dejavusans', 12)

def default(value, default):
  # return a default value
  # to avoid the "principle of least surprise" with mutable default arguments
  if value is None:
    return default
  return value

class NodeInput:
  def __init__(self, name, typ):
    self.pos = (0, 0) # the position of the draggable circle relative to the connection point
    self.name = name
    self.typ = typ # i call it `typ` because `type` gives ugly ahh purple keyword formatting
    self.connected = True # i don't need to connect backwards right?
    self.buffer = []
    self.updatesize()
  
  def abspos(self):
    return addpoints(self.pos, self.parent.pos, (0, self.parent.inputheights[self.parenti]))
  
  def socketrect(self):
    return (addpoints(self.abspos(), (-4, -4)), (8, 8))
  
  def updatesize(self):
    namesize = font.size(self.name)
    width = 5 + 2 + namesize[0]
    height = namesize[1]
    self.size = width, height
  
  def draw(self):
    display = pygame.surface.Surface(self.size, pygame.SRCALPHA)
    display.fill((0, 0, 0, 0))
    name = font.render(self.name, True, (0, 0, 0))
    display.blit(name, (5 + 2, 0))
    return display

class Node:
  # a node
  # can have inputs and outputs
  # and sliders? maybe like blender - slider or connection
  # inputs and outputs of types
  
  def __init__(self, pos = None, name = None, inputs = None, outputs = None, widgets = None):
    self.pos = default(pos, (0, 0))
    self.name = default(name, "DEFAULT NODE")
    self.inputs = default(inputs, [])
    for ii,i in enumerate(self.inputs):
      i.parent = self
      i.parenti = ii
    self.outputs = default(outputs, [])
    for oi,o in enumerate(self.outputs):
      o.parent = self
      o.parenti = oi
    self.widgets = default(widgets, [])
    self.updatesize()
    self.layoutconnections()
  
  def update(self):
    # update the outputs with the inputs
    # i'm not sure how this should work
    # push or pull?
    # push probably
    # read available input and push some output
    for w in self.widgets:
      w.update()
    pass
  
  def updatesize(self):
    namesize = font.size(self.name)
    width = max(
      namesize[0],
      # two 0's because max treats a single argument as an iterable
      max(*(i.size[0] for i in self.inputs), 0, 0) + max(*(o.size[0] for o in self.outputs), 0, 0),
      *(w.minwidth() for w in self.widgets)
    )
    height = (
      namesize[1] +
      max(sum(i.size[1] for i in self.inputs), sum(o.size[1] for o in self.outputs)) +
      sum(w.height() for w in self.widgets)
    )
    self.size = width, height
  
  def layoutconnections(self):
    # does this need to exist?
    # maybe not if all connections have the same height?
    # also i'm assuming the connections are centered vertically
    namesize = font.size(self.name)
    iy = namesize[1]
    self.inputheights = []
    for i in self.inputs:
      ih = i.size[1]
      self.inputheights.append(iy + ih / 2)
      iy += ih
    oy = namesize[1]
    self.outputheights = []
    for o in self.outputs:
      oh = o.size[1]
      self.outputheights.append(oy + oh / 2)
      oy += oh
  
  def draw(self):
    display = pygame.surface.Surface(self.size, pygame.SRCALPHA) # per pixel alpha because i want to have rounded corners <3
    display.fill((128, 128, 128))
    name = font.render(self.name, True, (0, 0, 0))
    display.blit(name, ((display.get_width() - name.get_width()) / 2, 0))
    iy = name.get_height()
    for i in self.inputs:
      ir = i.draw()
      display.blit(ir, (0, iy))
      iy += i.size[1]
    return display
  
  def bounds(self):
    return pygame.Rect(self.pos, self.size)
  
  def mousepressed(self, pos):
    # called when the node is clicked on
    # return True means captured by a gui element
    # meaning it won't get dragged
    return False
  
  def mousedragged(self, rel):
    # only called if mousepressed() returned True
    # deals with sliders etc
    pass

def addpoints(*ps):
  # tm
  return tuple(map(sum, zip(*ps)))

pygame.init()

display = pygame.display.set_mode((640, 480), pygame.RESIZABLE)
clock = pygame.time.Clock()

nodes = [Node(inputs = [NodeInput('the', 'none')]), Node()]

# focus: [NOFOCUS, None] | [FOCUSDRAGNODE, node] | [FOCUSNODE, node] | [FOCUSNODEINPUT, node, ii] | [FOCUSNODEOUTPUT, node, oi]
NOFOCUS         = 0
FOCUSDRAGNODE   = 1
FOCUSNODE       = 2
FOCUSNODEINPUT  = 3 # dragging the socket, specifically
FOCUSNODEOUTPUT = 4 # dragging the socket, specifically

focus = NOFOCUS,

while True:
  for event in pygame.event.get():
    if event.type == pygame.QUIT:
      sys.exit()
    if event.type == pygame.MOUSEBUTTONDOWN:
      #print(event)
      if event.button == 1:
        for i,node in enumerate(nodes):
          if node.bounds().collidepoint(event.pos):
            focus = FOCUSDRAGNODE, node
        #print(focusi)
        if focus[0] == FOCUSDRAGNODE:
          if focus[1].mousepressed(event.pos):
            focus = FOCUSNODE, node
        else:
          focus = NOFOCUS,
    if event.type == pygame.MOUSEMOTION:
      if focus[0] == FOCUSNODE:
        focus.mousedragged(event.rel)
      if focus[0] == FOCUSDRAGNODE:
        #print(focus.pos, event.rel)
        focus[1].pos = addpoints(focus[1].pos, event.rel)
    if event.type == pygame.MOUSEBUTTONUP:
      focus = NOFOCUS,
  display.fill((255, 255, 255))
  for node in nodes:
    display.blit(node.draw(), node.pos)
    for inp in node.inputs:
      pygame.draw.rect(display, (200, 200, 200), inp.socketrect())
  pygame.display.update()
  clock.tick(60)