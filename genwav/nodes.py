import pygame
import sys
import math

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
    self.connected = None
    self.buffer = []
    self.updatesize()
  
  def abspos(self):
    return addpoints(self.pos, self.wirepos())
  
  def wirepos(self):
    return addpoints(self.parent.pos, (0, self.parent.inputheights[self.parenti]))
  
  def socketrect(self):
    return pygame.Rect(addpoints(self.abspos(), (-4, -4)), (8, 8))
  
  def updatesize(self):
    namesize = font.size(self.name)
    width = 4 + 2 + namesize[0]
    height = namesize[1]
    self.size = width, height
  
  def draw(self):
    display = pygame.surface.Surface(self.size, pygame.SRCALPHA)
    display.fill((0, 0, 0, 0))
    name = font.render(self.name, True, (0, 0, 0))
    display.blit(name, (4 + 2, 0))
    return display
  
  def connect(self, other):
    if other is not None:
      self.connected = other
      self.connected.connected.append(self)
      self.pos = (0, 0)
      self.connected.pos = (0, 0)
  
  def disconnect(self):
    if self.connected is not None:
      self.connected.connected.remove(self)
      self.connected = None

class NodeOutput:
  def __init__(self, name, typ):
    self.pos = (0, 0) # the position of the draggable circle relative to the connection point
    self.name = name
    self.typ = typ # i call it `typ` because `type` gives ugly ahh purple keyword formatting
    self.connected = [] # the inputs this sends to
    self.updatesize()
  
  def abspos(self):
    return addpoints(self.pos, self.wirepos())
  
  def wirepos(self):
    return addpoints(self.parent.pos, (self.parent.size[0], self.parent.outputheights[self.parenti]))
  
  def socketrect(self):
    return pygame.Rect(addpoints(self.abspos(), (-4, -4)), (8, 8))
  
  def updatesize(self):
    namesize = font.size(self.name)
    width = namesize[0] + 2 + 4
    height = namesize[1]
    self.size = width, height
  
  def draw(self):
    display = pygame.surface.Surface(self.size, pygame.SRCALPHA)
    display.fill((0, 0, 0, 0))
    name = font.render(self.name, True, (0, 0, 0))
    display.blit(name, (0, 0))
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
      max(*(i.size[0] for i in self.inputs), 0, 0) + 5 + max(*(o.size[0] for o in self.outputs), 0, 0),
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
    oy = name.get_height()
    for o in self.outputs:
      or_ = o.draw()
      display.blit(or_, (self.size[0] - or_.get_width(), oy))
      oy += o.size[1]
    return display
  
  def bounds(self):
    return pygame.Rect(self.pos, self.size)
  
  def captures(self, pos):
    # called when the node is clicked on
    # return True means captured by a gui element
    # meaning it won't get dragged
    return False
  
  def mousepressed(self, pos):
    # called when the node is clicked on
    # return True means captured by a gui element
    # meaning it won't get dragged
    return False
  
  def mousedragged(self, rel):
    # only called if mousepressed() returned True
    # deals with sliders etc
    pass
  
  def mousereleased(self):
    # only called if mousepressed() returned True
    # deals with sliders etc
    pass

def addpoints(*ps):
  # tm
  return tuple(map(sum, zip(*ps)))

def distance2(p1, p2):
  return sum((c1 - c2) ** 2 for c1,c2 in zip(p1, p2))

def distance(p1, p2):
  return math.sqrt(distance2(p1, p2))

pygame.init()

display = pygame.display.set_mode((640, 480), pygame.RESIZABLE)
clock = pygame.time.Clock()

nodes = [
  Node(inputs = [NodeInput('the', 'none')], outputs = [NodeOutput('weweweweweweew', 'none')]),
  Node(inputs = [NodeInput('the', 'none')], outputs = [NodeOutput('weweweweweweew', 'none')]),
  Node(),
]

# focus: (NOFOCUS) | (FOCUSDRAGNODE, node) | (FOCUSNODE, node) | (FOCUSNODEINPUT, inp) | (FOCUSNODEOUTPUT, outp)
NOFOCUS         = 0, # comma to make it a tuple so i don't need a comma everywhere i use it
FOCUSDRAGNODE   = 1 # dragging the node
FOCUSNODE       = 2 # probably dragging a slider or something idk
FOCUSNODEINPUT  = 3 # dragging an input socket
FOCUSNODEOUTPUT = 4 # dragging an output socket

focus = NOFOCUS

while True:
  mpos = pygame.mouse.get_pos()
  nextfocus = NOFOCUS
  for i,node in enumerate(nodes):
    if node.bounds().collidepoint(mpos):
      nextfocus = FOCUSDRAGNODE, node
    for inp in node.inputs:
      if inp.socketrect().collidepoint(mpos):
        nextfocus = FOCUSNODEINPUT, inp
    for outp in node.outputs:
      if outp.socketrect().collidepoint(mpos):
        nextfocus = FOCUSNODEOUTPUT, outp
  #print(focusi)
  if focus[0] == FOCUSDRAGNODE:
    if focus[1].captures(mpos):
      nextfocus = FOCUSNODE, node
  closestoutput = None
  closestinput = None
  if focus[0] == FOCUSNODEINPUT:
    mindist = 30
    for node in nodes:
      fpos = focus[1].abspos()
      for outp in node.outputs:
        dist = distance(outp.abspos(), fpos)
        if dist < mindist:
          mindist = dist
          closestoutput = outp
  if focus[0] == FOCUSNODEOUTPUT:
    mindist = 30
    for node in nodes:
      fpos = focus[1].abspos()
      for inp in node.inputs:
        dist = distance(inp.abspos(), fpos)
        if dist < mindist:
          mindist = dist
          closestinput = inp
  for event in pygame.event.get():
    if event.type == pygame.QUIT:
      sys.exit()
    if event.type == pygame.MOUSEBUTTONDOWN:
      #print(event)
      if event.button == 1:
        focus = nextfocus
      if focus[0] == FOCUSNODE:
        focus[1].mousepressed(event.pos) # i'm assuming the mouse position hasn't changed
      if focus[0] == FOCUSNODEINPUT:
        focus[1].disconnect()
    if event.type == pygame.MOUSEMOTION:
      if focus[0] == FOCUSNODE:
        focus[1].mousedragged(event.rel)
      if focus[0] == FOCUSDRAGNODE:
        #print(focus.pos, event.rel)
        focus[1].pos = addpoints(focus[1].pos, event.rel)
      if focus[0] == FOCUSNODEINPUT:
        #print(focus.pos, event.rel)
        focus[1].pos = addpoints(focus[1].pos, event.rel)
      if focus[0] == FOCUSNODEOUTPUT:
        #print(focus.pos, event.rel)
        focus[1].pos = addpoints(focus[1].pos, event.rel)
    if event.type == pygame.MOUSEBUTTONUP:
      if focus[0] == FOCUSNODE:
        focus[1].mousereleased()
      if focus[0] == FOCUSNODEINPUT:
        focus[1].connect(closestoutput)
      if focus[0] == FOCUSNODEOUTPUT:
        closestinput.connect(focus[1])
      focus = NOFOCUS
  display.fill((255, 255, 255))
  for node in nodes:
    display.blit(node.draw(), node.pos)
    for inp in node.inputs:
      if inp.connected is not None:
        pygame.draw.line(display, (0, 0, 0), inp.wirepos(), inp.connected.wirepos())
      else:
        pygame.draw.line(display, (0, 0, 0), inp.wirepos(), inp.abspos())
      # change the color if this one is selected or can get connected
      color = (200, 200, 200)
      if focus[0] == FOCUSNODEINPUT and inp is focus[1]:
        color = (255, 255, 100)
      if focus[0] == FOCUSNODEOUTPUT and inp is closestinput:
        color = (150, 150, 255)
      pygame.draw.rect(display, color, inp.socketrect())
    for outp in node.outputs:
      pygame.draw.line(display, (0, 0, 0), outp.wirepos(), outp.abspos())
      # change the color if this one is selected or can get connected
      color = (200, 200, 200)
      if focus[0] == FOCUSNODEOUTPUT and outp is focus[1]:
        color = (255, 255, 100)
      if focus[0] == FOCUSNODEINPUT and outp is closestoutput:
        color = (150, 150, 255)
      pygame.draw.rect(display, color, outp.socketrect())
  pygame.display.update()
  clock.tick(60)