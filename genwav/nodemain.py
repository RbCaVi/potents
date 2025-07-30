import pygame
import sys

from nodes import Node, NodeInput, NodeOutput, Widget, addpoints, distance

pygame.init()

display = pygame.display.set_mode((640, 480), pygame.RESIZABLE)
clock = pygame.time.Clock()

nodes = [
  Node(inputs = [NodeInput('the', 'none')], outputs = [NodeOutput('weweweweweweew', 'none')]),
  Node(inputs = [NodeInput('the', 'none')], outputs = [NodeOutput('weweweweweweew', 'jej')], widgets = [Widget()]),
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
  if nextfocus[0] == FOCUSDRAGNODE:
    if nextfocus[1].captures(mpos):
      nextfocus = FOCUSNODE, nextfocus[1]
  closestoutput = None
  closestinput = None
  if nextfocus[0] == FOCUSNODEINPUT:
    mindist = 30
    for node in nodes:
      fpos = nextfocus[1].abspos()
      for outp in node.outputs:
        dist = distance(outp.abspos(), fpos)
        if dist < mindist:
          mindist = dist
          closestoutput = outp
  if nextfocus[0] == FOCUSNODEOUTPUT:
    mindist = 30
    for node in nodes:
      fpos = nextfocus[1].abspos()
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
        if closestoutput is not None:
          focus[1].connect(closestoutput)
      if focus[0] == FOCUSNODEOUTPUT:
        if closestinput is not None:
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
        if closestinput.typ == focus[1].typ:
          color = (150, 150, 255)
        else:
          color = (255, 150, 150)
      pygame.draw.rect(display, color, inp.socketrect())
    for outp in node.outputs:
      pygame.draw.line(display, (0, 0, 0), outp.wirepos(), outp.abspos())
      # change the color if this one is selected or can get connected
      color = (200, 200, 200)
      if focus[0] == FOCUSNODEOUTPUT and outp is focus[1]:
        color = (255, 255, 100)
      if focus[0] == FOCUSNODEINPUT and outp is closestoutput:
        if closestoutput.typ == focus[1].typ:
          color = (150, 150, 255)
        else:
          color = (255, 150, 150)
      pygame.draw.rect(display, color, outp.socketrect())
  pygame.display.update()
  clock.tick(60)