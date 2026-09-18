# state space explorer
# graph traversal

import random
import pygame
import pygame.locals
from OpenGL.GL import *
import sys

import numpy
from ctypes import *

def strset(s, i, value):
  return ''.join(value if j == i else c for j,c in enumerate(s))

def gridset(grid, x, y, value):
  return tuple(strset(col, y, value) if i == x else col for i,col in enumerate(grid))

# a function that takes a state and returns the possible next states
def nextstates(state):
  (x,y),grid = state
  for dx,dy in [(0, 1), (1, 0), (0, -1), (-1, 0)]:
    if grid[x + dx][y + dy] == ' ':
      yield ((x + dx, y + dy), grid), 0
    if grid[x + dx][y + dy] == 'o' and grid[x + dx * 2][y + dy * 2] == ' ':
      yield ((x + dx, y + dy), gridset(gridset(grid, x + dx, y + dy, ' '), x + dx * 2, y + dy * 2, 'o')), 1

def renderstate(surface, state):
  ppos,grid = state
  for i,j,c in [(i, j, c) for i,row in enumerate(grid) for j,c in enumerate(row)]:
    color = None
    if c == '#':
      color = (247, 210, 88)
    if c == ' ':
      color = (186, 186, 186)
    if c == 'o':
      color = (34, 162, 247)
    pygame.draw.rect(surface, color, (i * 20 + 50, j * 20 + 50, 20, 20))
  pygame.draw.rect(surface, (255, 0, 255), (ppos[0] * 20 + 52, ppos[1] * 20 + 52, 16, 16))

def renderstate2(surface, state): # for collapsed
  grid = next(iter(state))[1]
  for i,j,c in [(i, j, c) for i,row in enumerate(grid) for j,c in enumerate(row)]:
    color = None
    if c == '#':
      color = (247, 210, 88)
    if c == ' ':
      color = (186, 186, 186)
    if c == 'o':
      color = (34, 162, 247)
    pygame.draw.rect(surface, color, (i * 20 + 50, j * 20 + 50, 20, 20))
  for ppos,grid in state:
    pygame.draw.rect(surface, (255, 0, 255), (ppos[0] * 20 + 52, ppos[1] * 20 + 52, 16, 16))

# a traversal function
def traverse(initial, nextstates):
  states = {}
  newstates = {initial}
  while True:
    nextnewstates = set()
    for state in newstates:
      added = dict(nextstates(state))
      states[state] = added
      for state in added:
        if state not in states:
          nextnewstates.add(state)
    if len(newstates) == 0:
      return states
    newstates = nextnewstates

def collapse(graph):
  # collapse edges of type 0
  nodes = set(graph)
  quotient = {}
  collapsed = {}
  while len(nodes) > 0:
    # traversal of the subgraph reachable from a node using only edges of type 0
    # probably breadth first but it's implementation defined probably
    tovisit = {nodes.pop()}
    group = set()
    while len(tovisit) > 0:
      node = tovisit.pop()
      group.add(node)
      quotient[node] = group
      for nextnode,edgekind in graph[node].items():
        if edgekind == 0 and nextnode in nodes:
          nodes.remove(nextnode)
          tovisit.add(nextnode)
    collapsed[frozenset(group)] = {}
  for n1,n2,kind in ((n1, n2, kind) for n1,edges in graph.items() for n2,kind in edges.items()):
    if kind == 0:
      continue
    if frozenset(quotient[n1]) not in collapsed:
      collapsed[frozenset(quotient[n1])] = {}
    collapsed[frozenset(quotient[n1])][frozenset(quotient[n2])] = kind # assume there is only one kind of edge between any two groups
  return collapsed

def toindexes(graph):
  vertices = [*graph]
  mapping = {k:i for i,k in enumerate(vertices)}
  return vertices, {mapping[n1]:{mapping[n2]:edge for n2,edge in edges.items()} for n1,edges in graph.items()}

fullgraph = traverse((
  (1, 2),
  (
    '######',
    '##  ##',
    '# oo #',
    '##  ##',
    '######',
  ),
), nextstates)

vertices,graph = toindexes(fullgraph)

print(vertices, graph)

print(toindexes(collapse(fullgraph)))

#vertices,graph = toindexes(collapse(fullgraph))

mask = numpy.full((len(graph), len(graph), 3), True, dtype = numpy.bool)
edges = []
for i in graph:
  for j in graph[i]:
    if i == j:
      continue
    mask[i, j] = mask[j, i] = False, False, False
    edges.append((i, j, graph[i][j]))

edges = numpy.array(edges, dtype = numpy.int32)

pos = numpy.array([(random.uniform(-1, 1), random.uniform(-1, 1), random.uniform(-1, 1) * 0) for k in graph], dtype = numpy.float32)
cs = 0.02
l = 0.1
cr = 0.005

dpos = [(0, 0, 0) for k in graph]

pygame.init()

pygame.display.gl_set_attribute(pygame.GL_CONTEXT_MAJOR_VERSION, 3)
pygame.display.gl_set_attribute(pygame.GL_CONTEXT_MINOR_VERSION, 1)
pygame.display.gl_set_attribute(pygame.GL_CONTEXT_PROFILE_MASK, pygame.GL_CONTEXT_PROFILE_CORE)

size = (600, 600)
pygame.display.set_mode(size, pygame.locals.DOUBLEBUF | pygame.locals.OPENGL)


#glEnable(GL_DEPTH_TEST)

glClearColor(0.0, 0.0, 0.0, 0.0)

def compileshader(source, kind):
  shader = glCreateShader(kind)
  glShaderSource(shader, [source], None)
  glCompileShader(shader)
  assert glGetShaderiv(shader, GL_COMPILE_STATUS), glGetShaderInfoLog(shader)
  return shader

def compileprogram(vertex_shader_source, fragment_shader_source, bindings = {}):
  vertex_shader = compileshader(vertex_shader_source, GL_VERTEX_SHADER)
  fragment_shader = compileshader(fragment_shader_source, GL_FRAGMENT_SHADER)

  program = glCreateProgram()
  glAttachShader(program, vertex_shader)
  glAttachShader(program, fragment_shader)
  for name,i in bindings.items():
    glBindAttribLocation(program, i, name)
  glLinkProgram(program)
  assert glGetProgramiv(program, GL_LINK_STATUS), glGetProgramInfoLog(program)
  glDeleteShader(vertex_shader)
  glDeleteShader(fragment_shader)

  return program

program = compileprogram("""
#version 120

uniform float scale;

attribute vec2 coord;
attribute vec3 off;

void main() {
  gl_Position = vec4(coord * 0.1 + off.xy * scale, 0, 1.0);
}
""", """
#version 120

void main() {
  gl_FragData[0] = vec4(1.0, 0.0, 0.0, 1.0);
}
""", {'coord': 0, 'off': 1})

program2 = compileprogram("""
#version 120

uniform float scale;

attribute vec2 coord;
attribute vec3 start;
attribute vec3 end;
attribute float edgekind;
varying float f_edgekind;

void main() {
  vec2 dir = normalize(end.xy - start.xy);
  vec2 perp = vec2(dir.y, -dir.x);
  if (coord.x < 0.5) {
    gl_Position = vec4(start.xy * scale + (dir * coord.x + perp * coord.y) * 0.2, 0, 1.0);
  } else {
    gl_Position = vec4(end.xy * scale + (dir * (coord.x - 1) + perp * coord.y) * 0.2, 0, 1.0);
  }
  f_edgekind = edgekind;
}
""", """
#version 120

varying float f_edgekind;

void main() {
  if (f_edgekind < 0.5) {
    gl_FragData[0] = vec4(1.0, 1.0, 1.0, 1.0);
  } else {
    gl_FragData[0] = vec4(1.0, 1.0, 0.0, 1.0);
  }
}
""", {'coord': 2, 'start': 3, 'end': 4, 'edgekind': 5})

program3 = compileprogram("""
#version 120

attribute vec2 coord;
varying vec2 uv;

void main() {
  uv = (coord + 1) / 2;
  gl_Position = vec4(coord, 0.0, 1.0);
}
""", """
#version 120

uniform sampler2D img;
varying vec2 uv;

void main() {
  gl_FragData[0] = texture2D(img, vec2(uv.x, 1 - uv.y));
  //gl_FragData[0] = vec4(uv, 0.0, 1.0);
  //gl_FragData[0] = vec4(0.0, 1.0, 1.0, 1.0);
}
""", {'coord': 6, 'img': 7})

def setfloat(program, name, f):
  uniform = glGetUniformLocation(program, name)
  glUniform1f(uniform, f)

def setint(program, name, i):
  uniform = glGetUniformLocation(program, name)
  glUniform1i(uniform, i)

vertdata = numpy.array([
  -0.1,-0.1,
  -0.1, 0.1,
   0.1, 0.1,
   0.1,-0.1,
  -0.1,-0.1,
   0.1, 0.1,
], dtype = numpy.float32)

vertdata2 = numpy.array([
   0, 0,
   1, 0,
   1, 0,
   0.9, 0.05,
   1, 0,
   0.9, -0.05,
   ], dtype = numpy.float32)

vertdata3 = numpy.array([
  -1,-1,
  -1, 1,
   1, 1,
   1,-1,
  -1,-1,
   1, 1,
], dtype = numpy.float32)

def createArray(size): # size is the number of floats in a vertex
  handle = glGenBuffers(1)
  return handle, size

def loadFloatArray(handle, data, count, kind = GL_STATIC_DRAW):
  glBindBuffer(GL_ARRAY_BUFFER, handle[0])
  glBufferData(GL_ARRAY_BUFFER, count * handle[1] * sizeof(c_float), data, kind)

def applyvd(program, handle, name, size, offset):
  attr = glGetAttribLocation(program, name)
  glBindBuffer(GL_ARRAY_BUFFER, handle[0])
  glVertexAttribPointer(attr, size, GL_FLOAT, False, handle[1] * sizeof(c_float), c_void_p(offset * sizeof(c_float)))
  return attr

def enableAttr(handle, attr):
  glBindBuffer(GL_ARRAY_BUFFER, handle[0])
  glEnableVertexAttribArray(attr)

def disableAttr(handle, attr):
  glBindBuffer(GL_ARRAY_BUFFER, handle[0])
  glDisableVertexAttribArray(attr)

glUseProgram(program)
verts = createArray(2)
loadFloatArray(verts, vertdata, 6)
coordattr = applyvd(program, verts, "coord", 2, 0)

poss = createArray(3)
posattr = applyvd(program, poss, "off", 3, 0)
glVertexAttribDivisor(posattr, 1)

glUseProgram(program2)
verts2 = createArray(2)
loadFloatArray(verts2, vertdata2, 6)
coordattr2 = applyvd(program2, verts2, "coord", 2, 0)

edgedata = createArray(7)
startattr = applyvd(program2, edgedata, "start", 3, 0)
glVertexAttribDivisor(startattr, 1)
endattr = applyvd(program2, edgedata, "end", 3, 3)
glVertexAttribDivisor(endattr, 1)
edgekindattr = applyvd(program2, edgedata, "edgekind", 1, 6)
glVertexAttribDivisor(edgekindattr, 1)

glUseProgram(program3)
verts3 = createArray(2)
loadFloatArray(verts3, vertdata3, 6)
coordattr3 = applyvd(program3, verts3, "coord", 2, 0)

screentexture = glGenTextures(1)
glBindTexture(GL_TEXTURE_2D, screentexture)
glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST)
glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST)
glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE)
glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE)
screen = pygame.Surface(size)

pressedi = None
mind = 1

scale = 0.1

while True:
  screen.fill((0, 0, 0))
  pygame.draw.rect(screen, (255, 255, 255), (10, 10, 20, 20))

  if mind < 0.2:
    state = vertices[mini]
    renderstate(screen, state)

  rgba_surface = pygame.image.tostring(screen, 'RGBA')
  glActiveTexture(GL_TEXTURE1)
  glBindTexture(GL_TEXTURE_2D, screentexture)
  glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, size[0], size[1], 0, GL_RGBA, GL_UNSIGNED_BYTE, rgba_surface)

  glClear(GL_COLOR_BUFFER_BIT # clear the background
      | GL_DEPTH_BUFFER_BIT)  # and the depth buffer

  glUseProgram(program3)
  setint(program3, 'img', screentexture)

  glEnable(GL_TEXTURE_2D)
  enableAttr(verts3, coordattr3)
  glDrawArrays(GL_TRIANGLES, 0, 6)
  glDisable(GL_TEXTURE_2D)
  disableAttr(verts3, coordattr3)

  glUseProgram(program)
  loadFloatArray(poss, pos.flatten(), len(pos), GL_DYNAMIC_DRAW)
  setfloat(program, 'scale', scale)

  enableAttr(verts, coordattr)
  enableAttr(poss, posattr)
  glDrawArraysInstanced(GL_TRIANGLES, 0, 6, len(pos))
  disableAttr(verts, coordattr)
  disableAttr(poss, posattr)

  glUseProgram(program2)
  loadFloatArray(edgedata, numpy.concatenate((pos[edges[:, 0]], pos[edges[:, 1]], edges[:, 2, numpy.newaxis].astype(numpy.float32)), axis = 1).flatten(), len(edges), GL_DYNAMIC_DRAW)
  setfloat(program2, 'scale', scale)

  enableAttr(verts2, coordattr2)
  enableAttr(edgedata, startattr)
  enableAttr(edgedata, endattr)
  enableAttr(edgedata, edgekindattr)
  glDrawArraysInstanced(GL_LINES, 0, 6, len(edges))
  disableAttr(verts2, coordattr2)
  disableAttr(edgedata, startattr)
  disableAttr(edgedata, endattr)
  enableAttr(edgedata, edgekindattr)

  pygame.display.flip()
  pygame.time.wait(10)

  disps = pos[numpy.newaxis, :, :] - pos[:, numpy.newaxis, :]
  dist2s = numpy.sum(disps ** 2, axis = 2)
  dists = numpy.sqrt(dist2s)
  dirs = disps / dists[:, :, numpy.newaxis]
  
  fattrs = numpy.ma.MaskedArray(-numpy.nan_to_num(cs * numpy.log(dists[:, :, numpy.newaxis] / l) * dirs), mask).filled(0)
  freps = numpy.nan_to_num(cr / dist2s[:, :, numpy.newaxis] * dirs)
  
  fs = fattrs + freps
  pos += fs.sum(0)

  mpos = [*(numpy.array(pygame.mouse.get_pos()) / size * 2 - 1) / scale, 0]
  mpos[1] = -mpos[1]
  
  if pressedi is not None:
    pos[pressedi] = mpos

  mind = 1
  mini = None
  for i,npos in enumerate(pos):
    if ((mpos - npos) ** 2).sum() < mind:
      mini = i
      mind = ((mpos - npos) ** 2).sum()

  # Events management
  for event in pygame.event.get():
    if event.type == pygame.QUIT:
      pygame.quit()
      sys.exit()
    if event.type == pygame.MOUSEBUTTONDOWN:
      print(mind, mini)
      if mind < 0.2:
        pressedi = mini
    if event.type == pygame.MOUSEBUTTONUP:
      pressedi = None

