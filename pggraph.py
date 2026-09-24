# state space explorer
# graph traversal

import random
import pygame
import pygame.locals
from OpenGL.GL import *
import sys
import math
import collections
import numpy
from ctypes import *

import contextlib

from pyglm import glm

pygame.init()

# request a 3.1 opengl i guess
pygame.display.gl_set_attribute(pygame.GL_CONTEXT_MAJOR_VERSION, 4)
pygame.display.gl_set_attribute(pygame.GL_CONTEXT_MINOR_VERSION, 3)
pygame.display.gl_set_attribute(pygame.GL_CONTEXT_PROFILE_MASK, pygame.GL_CONTEXT_PROFILE_CORE)

# spring layout parameters
cs = 0.1
l = 0.1
cr = 0.02

interactrad = 0.05

# compile a vertex or fragment (or other kind? idk) shader from glsl sourcecode
# return the shader handle
def compileshader(source, kind):
  shader = glCreateShader(kind)
  glShaderSource(shader, [source], None)
  glCompileShader(shader)
  assert glGetShaderiv(shader, GL_COMPILE_STATUS), glGetShaderInfoLog(shader)
  return shader

# compile and link a shader program from vertex and fragment shader glsl source code
# variable locations can optionally be given in the third argument
# return the program handle
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

  return Program(program)

# compile and link a compute shader program from glsl source code
# return the program handle
def compilecomputeprogram(compute_shader_source):
  compute_shader = compileshader(compute_shader_source, GL_COMPUTE_SHADER)

  program = glCreateProgram()
  glAttachShader(program, compute_shader)
  glLinkProgram(program)
  assert glGetProgramiv(program, GL_LINK_STATUS), glGetProgramInfoLog(program)
  glDeleteShader(compute_shader)

  return Program(program)

class Program(collections.namedtuple('Program', ['name'])):
  def use(self):
    glUseProgram(self.name)

  def uniform(self, name):
    return glGetUniformLocation(self.name, name)

  def attr(self, name):
    return glGetAttribLocation(self.name, name)

  def bindssb(self, name, index):
    glShaderStorageBlockBinding(self.name, glGetProgramResourceIndex(self.name, GL_SHADER_STORAGE_BLOCK, name), index)

  def __enter__(self):
    self._last = glGetIntegerv(GL_CURRENT_PROGRAM)
    self.use()
    return

  def __exit__(self, _1, _2, _3):
    glUseProgram(self._last)
    self._last = None
    return False

# set uniform variables
def setfloat(uniform, f):
  glUniform1f(uniform, f)

def setint(uniform, i):
  glUniform1i(uniform, i)

def setmat4(uniform, m):
  glUniformMatrix4fv(uniform, 1, False, numpy.array(m).flatten())

def createVAO():
  return VertexArray(glGenVertexArrays(1))

class VertexArray(collections.namedtuple('VertexArray', ['name'])):
  def bind(self):
    glBindVertexArray(self.name)

  def __enter__(self):
    self._last = glGetIntegerv(GL_VERTEX_ARRAY_BINDING)
    self.bind()
    return

  def __exit__(self, _1, _2, _3):
    glBindVertexArray(self._last)
    self._last = None
    return False

class VertexBuffer(collections.namedtuple('VertexBuffer', ['name', 'size'])):
  # create an array buffer
  # pre "set" the stride (floats per vertex / instance)
  # because i think usually you would want to have
  # all the attributes stored in an array have the same stride
  # returns an array object
  @staticmethod
  def new(size): # size is the number of floats in a vertex
    name = glGenBuffers(1)
    return VertexBuffer(name, size)

  @staticmethod
  def new_data(data, kind = GL_STATIC_DRAW): # load data at construction
    count,size = data.shape
    return VertexBuffer.new(size).loadFloatArray(data, kind)

  # allocate the memory for it but don't put any data
  def declareFloatArray(self, count, kind = GL_STATIC_DRAW):
    self.bind()
    glBufferData(GL_ARRAY_BUFFER, count * self.size * sizeof(c_float), None, kind)
    return self

  # load a 2d numpy array of floats into an array buffer
  # it must have the same number of floats per vertex
  def loadFloatArray(self, data, kind = GL_STATIC_DRAW):
    count,size = data.shape
    assert self.size == size
    self.bind()
    glBufferData(GL_ARRAY_BUFFER, count * self.size * sizeof(c_float), data.flatten(), kind)
    return self

  # set a vertex attribute
  # returns an attribute object
  def applyvd(self, attr, size, offset):
    self.bind()
    glVertexAttribPointer(attr, size, GL_FLOAT, False, self.size * sizeof(c_float), c_void_p(offset * sizeof(c_float)))
    attr = VertexAttribute(self, attr)
    attr.enable()
    return attr

  # set an instance attribute
  # returns an attribute object
  def applyvdinstanced(self, attr, size, offset):
    attr = self.applyvd(attr, size, offset)
    glVertexAttribDivisor(attr.name, 1)
    return attr

  def bind(self):
    glBindBuffer(GL_ARRAY_BUFFER, self.name)

class VertexAttribute(collections.namedtuple('VertexAttribute', ['array', 'name'])):
  # whatever glEnableVertexAttribArray does
  def enable(self):
    self.array.bind()
    glEnableVertexAttribArray(self.name)

  # whatever glDisableVertexAttribArray does
  def disable(self):
    self.array.bind()
    glDisableVertexAttribArray(self.name)

  def __enter__(self):
    self.enable()
    return

  def __exit__(self, _1, _2, _3):
    self.disable()
    return False

# the shader and geometry for the graph nodes
nodeverts = numpy.array([
  [-0.01, -0.01],
  [-0.01,  0.01],
  [ 0.01,  0.01],
  [ 0.01, -0.01],
  [-0.01, -0.01],
  [ 0.01,  0.01],
], dtype = numpy.float32)

nodevert = """
#version 120

uniform mat4 transform; // camera transform

attribute vec2 coord; // node geometry
attribute vec3 off; // position of node
attribute float nodekind;
varying float f_nodekind;

void main() {
  // draw the node with a size and orientation unaffected by the transform
  gl_Position = vec4(off, 1.0) * transform * vec4(1, 1, 0.01, 1) + vec4(coord, 0, 0) + vec4(0, 0, -0.5, 0);
  f_nodekind = nodekind;
}
"""

nodefrag = """
#version 120

varying float f_nodekind;

void main() {
  // color the node by its kind
  if (f_nodekind < 0.5) {
    gl_FragData[0] = vec4(1.0, 0.0, 0.0, 1.0);
  } else {
    gl_FragData[0] = vec4(0.0, 1.0, 0.0, 1.0);
  }
}
"""

# the shader and geometry for the graph edges
arrowverts = numpy.array([
   [0  ,  0   ],
   [1  ,  0   ],
   [1  ,  0   ],
   [0.9,  0.05],
   [1  ,  0   ],
   [0.9, -0.05],
], dtype = numpy.float32)

arrowvert = """
#version 120

uniform mat4 transform; // camera transform

attribute vec2 coord; // arrow geometry
attribute vec3 start; // edge start point
attribute vec3 end; // edge end point
attribute float edgekind;
varying float f_edgekind;

void main() {
  // will need changes when i make this 3d
  vec3 dir = normalize((vec4(end - start, 0) * transform).xyz);
  vec3 perp = normalize(vec3(dir.y, -dir.x, 0));
  // stretch the arrow to keep the arrowhead the same size
  if (coord.x < 0.5) {
    gl_Position = vec4(start.xyz, 1.0) * transform * vec4(1, 1, 0.01, 1) + vec4((dir * coord.x + perp * coord.y) * 0.2, 0) + vec4(0, 0, -0.5, 0);
  } else {
    gl_Position = vec4(end.xyz, 1.0) * transform * vec4(1, 1, 0.01, 1) + vec4((dir * (coord.x - 1) + perp * coord.y) * 0.2, 0) + vec4(0, 0, -0.5, 0);
  }
  f_edgekind = edgekind;
}
"""

arrowfrag = """
#version 120

varying float f_edgekind;

void main() {
  // color the edge by its kind
  if (f_edgekind < 0.5) {
    gl_FragData[0] = vec4(1.0, 1.0, 1.0, 1.0);
  } else {
    gl_FragData[0] = vec4(1.0, 1.0, 0.0, 1.0);
  }
}
"""

# the shader and geometry for the pygame drawn background
bgverts = numpy.array([
  [-1, -1],
  [-1,  1],
  [ 1,  1],
  [ 1, -1],
  [-1, -1],
  [ 1,  1],
], dtype = numpy.float32)

bgvert = """
#version 120

attribute vec2 coord;
varying vec2 uv;

void main() {
  // convert screen space to uv
  uv = (coord + 1) / 2;
  gl_Position = vec4(coord, 0.0, 1.0);
}
"""

bgfrag = """
#version 120

uniform sampler2D img; // screen image from pygame
varying vec2 uv;

void main() {
  // y flipped because opengl y goes upward and pygame y goes downward
  gl_FragData[0] = texture2D(img, vec2(uv.x, 1 - uv.y));
}
"""

forcecompute = """
#version 430

layout(local_size_x = 128) in;

uniform float cs;
uniform float cr;
uniform float l;

uniform int size;

readonly restrict buffer EdgeStrength {
  float edgestrength[];
};

readonly restrict buffer Pos1 {
  vec3 pos1[];
};

writeonly restrict buffer Pos2 {
  vec3 pos2[];
};

vec3 calcforce(vec3 pos1, vec3 pos2, float strength) {
  vec3 disp = pos1 - pos2;
  float dist = length(disp);
  if (dist < 0.0001) {
    return vec3(0);
  }
  vec3 dir = disp / dist;
  float fattr = -clamp(log(dist / l), -1, 1);
  if (isnan(fattr) || isinf(fattr)) {
    fattr = 0;
  }
  float frep = 1 / (dist * dist);
  return (cs * strength * fattr + cr * frep) * dir;
}

void main() {
  uint i = gl_GlobalInvocationID.x;
  if (i >= size) {
    return;
  }
  vec3 posi = pos1[i];
  vec3 pos = pos1[i];
  for (uint j = 0; j < size; j++) {
    vec3 posj = pos1[j];
    pos += calcforce(posi, posj, edgestrength[i * size + j]);
  }
  pos2[i] = pos;
}
"""

edgecompute = """
#version 430

layout(local_size_x = 128) in;

uniform int size;

readonly restrict buffer Edges {
  vec2 edges[];
};

readonly restrict buffer Pos {
  vec3 pos[];
};

struct edge {
  vec3 start;
  vec3 end;
  float kind;
};

writeonly restrict buffer EdgePos {
  edge edgepos[];
};

void main() {
  uint i = gl_GlobalInvocationID.x;
  if (i >= size) {
    return;
  }
  edgepos[i].start = pos[int(floor(edges[i].x + 0.5))];
  edgepos[i].end = pos[int(floor(edges[i].y + 0.5))];
}
"""

def run(vertices, graph, kinds, renderstate):
  # create a mask of which edges have attraction forces applied
  # and a list of edges
  edgestrengthdata = numpy.full((len(graph), len(graph)), 0, dtype = numpy.float32)
  edges = []
  edgekinds = []
  for i in graph:
    for j in graph[i]:
      if i == j:
        continue
      edgestrengthdata[i, j] += 1
      edgestrengthdata[j, i] += 1
      edges.append((i, j))
      edgekinds.append(graph[i][j])

  edges = numpy.array(edges, dtype = numpy.int32).reshape((len(edges), 2))
  edgekinds = numpy.array(edgekinds, dtype = numpy.int32).reshape((len(edges), 1))

  kinds = numpy.array([kinds[v] for v in vertices])

  # initialize the node positions
  pos = numpy.array([(random.uniform(-1, 1), random.uniform(-1, 1), random.uniform(-1, 1)) for k in graph], dtype = numpy.float32)

  # initialize the window
  size = (600, 600)
  pygame.display.set_mode(size, pygame.locals.DOUBLEBUF | pygame.locals.OPENGL)

  glClearColor(0.0, 0.0, 0.0, 0.0)
  glEnable(GL_DEPTH_TEST)

  # compile the programs and set up their geometry and attributes
  nodeprogram = compileprogram(nodevert, nodefrag)
  arrowprogram = compileprogram(arrowvert, arrowfrag)
  bgprogram = compileprogram(bgvert, bgfrag)
  forceprogram = compilecomputeprogram(forcecompute)
  edgeprogram = compilecomputeprogram(edgecompute)

  with nodeprogram:
    nodecoords = VertexBuffer.new_data(nodeverts)
    poss1 = VertexBuffer.new(4)
    poss2 = VertexBuffer.new(4)
    nodekinds = VertexBuffer.new(1)

    nodevao1 = createVAO()
    with nodevao1:
      nodecoords.applyvd(nodeprogram.attr("coord"), 2, 0)
      poss1.applyvdinstanced(nodeprogram.attr("off"), 3, 0)
      nodekinds.applyvdinstanced(nodeprogram.attr("nodekind"), 1, 0)

    nodevao2 = createVAO()
    with nodevao2:
      nodecoords.applyvd(nodeprogram.attr("coord"), 2, 0)
      poss2.applyvdinstanced(nodeprogram.attr("off"), 3, 0)
      nodekinds.applyvdinstanced(nodeprogram.attr("nodekind"), 1, 0)

  with arrowprogram:
    arrowvao = createVAO()
    with arrowvao:
      VertexBuffer.new_data(arrowverts).applyvd(arrowprogram.attr("coord"), 2, 0)

      edgekindsdata = VertexBuffer.new(1)
      edgekindsdata.applyvdinstanced(arrowprogram.attr("edgekind"), 1, 0)

      edgedata = VertexBuffer.new(8)
      edgedata.applyvdinstanced(arrowprogram.attr("start"), 3, 0)
      edgedata.applyvdinstanced(arrowprogram.attr("end"), 3, 4)

  with bgprogram:
    bgvao = createVAO()
    with bgvao:
      VertexBuffer.new_data(bgverts).applyvd(bgprogram.attr("coord"), 2, 0)

  with forceprogram:
    setfloat(forceprogram.uniform('cs'), cs)
    setfloat(forceprogram.uniform('cr'), cr)
    setfloat(forceprogram.uniform('l'), l)

    forceprogram.bindssb("Pos1", 0)
    forceprogram.bindssb("Pos2", 1)
    forceprogram.bindssb("EdgeStrength", 2)

    edgestrength = VertexBuffer.new_data(edgestrengthdata)
    glBindBufferBase(GL_SHADER_STORAGE_BUFFER, 2, edgestrength.name)

  with edgeprogram:
    edgeprogram.bindssb("Edges", 3)
    edgeprogram.bindssb("Pos", 1)
    edgeprogram.bindssb("EdgePos", 5)

    edgesbuffer = VertexBuffer.new_data(edges.astype(numpy.float32))
    glBindBufferBase(GL_SHADER_STORAGE_BUFFER, 3, edgesbuffer.name)
    glBindBufferBase(GL_SHADER_STORAGE_BUFFER, 5, edgedata.name)

  # create a texture for pygame to render to
  screentexture = glGenTextures(1)
  glBindTexture(GL_TEXTURE_2D, screentexture)
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST)
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST)
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE)
  glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE)
  screen = pygame.Surface(size)

  pressedi = None # index of pressed node
  mind = 1 # minimum distance from mouse pointer to node

  transform = glm.scale(glm.vec3(0.2, 0.2, 0.2)) * glm.rotate(0.5, glm.vec3(0, 0, 1)) # current transform

  poss1.declareFloatArray(len(pos), GL_DYNAMIC_DRAW)
  poss2.loadFloatArray(numpy.concatenate((
    pos,
    pos[:, 1, numpy.newaxis],
  ), axis = 1), GL_DYNAMIC_DRAW)
  edgedata.declareFloatArray(len(edges), GL_DYNAMIC_DRAW)
  edgekindsdata.loadFloatArray(numpy.concatenate((
    edgekinds.astype(numpy.float32),
  ), axis = 1), GL_DYNAMIC_DRAW)
  nodekinds.loadFloatArray(kinds[:, numpy.newaxis].astype(numpy.float32), GL_DYNAMIC_DRAW)

  while True:
    screen.fill((0, 0, 0))
    pygame.draw.rect(screen, (255, 255, 255), (10, 10, 20, 20))

    # draw the currently hovered node
    if mind < interactrad:
      state = vertices[mini]
      renderstate(screen, state)

    # debug visualization
    # positions for mouse interaction
    '''
    for npos in pos:
      npost = transform * glm.vec4(npos, 1)
      np = npost.xy / npost.w
      pygame.draw.rect(screen, (255, 255, 255), ((np.x / 2 + .5) * size[0], (1 - np.y / 2 - .5) * size[1], 20, 20))
    '''

    # draw the pygame screen screen to the opengl screen texture
    glActiveTexture(GL_TEXTURE1)
    glBindTexture(GL_TEXTURE_2D, screentexture)
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, size[0], size[1], 0, GL_RGBA, GL_UNSIGNED_BYTE, pygame.image.tostring(screen, 'RGBA'))

    glClear(GL_COLOR_BUFFER_BIT # clear the background
        | GL_DEPTH_BUFFER_BIT)  # and the depth buffer

    # draw the screen texture to the screen
    with bgprogram, bgvao:
      setint(bgprogram.uniform('img'), screentexture)

      glDrawArrays(GL_TRIANGLES, 0, 6)

    # draw the nodes
    nodevao2,nodevao1 = nodevao1,nodevao2 # swap position buffers
    with nodeprogram, nodevao1 as nodevao:
      setmat4(nodeprogram.uniform('transform'), transform)

      glDrawArraysInstanced(GL_TRIANGLES, 0, 6, len(pos))

    # draw the edges
    with arrowprogram, arrowvao:
      setmat4(nodeprogram.uniform('transform'), transform)

      glDrawArraysInstanced(GL_LINES, 0, 6, len(edges))

    # refresh the display and wait for framerate
    pygame.display.flip()
    pygame.time.wait(10)

    poss2,poss1 = poss1,poss2 # swap position buffers
    glBindBufferBase(GL_SHADER_STORAGE_BUFFER, 0, poss1.name)
    glBindBufferBase(GL_SHADER_STORAGE_BUFFER, 1, poss2.name)
    
    # save the position of the currently dragged node
    if pressedi is not None:
      if pressedi == -1:
        pass
      else:
        poss1.bind()
        savedpos = glGetBufferSubData(GL_ARRAY_BUFFER, pressedi * 4 * sizeof(c_float), 3 * sizeof(c_float)).view('f')

    # compute forces on vertices
    with forceprogram:
      setint(forceprogram.uniform('size'), len(pos))

      glDispatchCompute(len(pos) // 128 + 1, 1, 1)

      glMemoryBarrier(GL_VERTEX_ATTRIB_ARRAY_BARRIER_BIT | GL_TEXTURE_FETCH_BARRIER_BIT) # make sure the changes are visible

    # mouse position and mouse movement
    mpos = glm.vec2(pygame.mouse.get_pos()) / size * 2 - 1
    mpos[1] = -mpos[1]
    dmpos = glm.vec2(pygame.mouse.get_rel()) / size * 2
    dmpos[1] = -dmpos[1]
    
    # handle dragging
    if pressedi is not None:
      if pressedi == -1:
        # drag camera
        transform = glm.translate(glm.vec3(dmpos, 0)) * transform
      else:
        # drag node
        newpos = savedpos + (glm.inverse(transform) * glm.vec4(dmpos, 0, 0)).xyz
        poss2.bind()
        glBufferSubData(GL_ARRAY_BUFFER, pressedi * 4 * sizeof(c_float), 3 * sizeof(c_float), newpos.view('b'))

    # move the edges
    # could i just use the shader storage buffer
    # hmm that would index twice for each vertex instead of twice for each edge
    with edgeprogram:
      setint(edgeprogram.uniform('size'), len(edges))

      glDispatchCompute(len(edges) // 128 + 1, 1, 1)

      glMemoryBarrier(GL_VERTEX_ATTRIB_ARRAY_BARRIER_BIT | GL_TEXTURE_FETCH_BARRIER_BIT) # make sure the changes are visible

    if pygame.mouse.get_pressed()[2]: # right mouse - rotate view
      # cross mouse movement with 0 0 1
      # to get a rotation axis perpendicular to mouse movement
      # then the magnitude is the sin of some angle idk
      axis = glm.cross(glm.normalize(glm.vec3(dmpos, 1)), glm.vec3(0, 0, 1))
      mag = glm.length(axis)
      if mag > 0.0000001: # idk some epsilon
        angle = math.asin(mag)
        transform = glm.rotate(angle, axis) * transform

    # find the closest node to the mouse
    # TIME: O(n)
    mind = math.inf
    mini = None
    poss2.bind()
    gpupos = glGetBufferSubData(GL_ARRAY_BUFFER, 0, len(pos) * 4 * sizeof(c_float)).view('f').reshape((-1, 4))
    for i,npos in enumerate(gpupos):
      npost = transform * glm.vec4(npos[:3], 1)
      np = npost.xy / npost.w
      if sum((mpos - np) ** 2) < mind:
        mini = i
        mind = sum((mpos - np) ** 2)

    # Events management
    for event in pygame.event.get():
      if event.type == pygame.QUIT: # close button
        pygame.quit()
        sys.exit()
      if event.type == pygame.MOUSEBUTTONDOWN:
        #print(event, event.button)
        if event.button == 1: # left mouse
          if mind < interactrad:
            pressedi = mini # if the mouse is close to a node, drag it
          else:
            pressedi = -1 # otherwise, drag the camera
        elif event.button == 4: # scroll up
          transform = transform * glm.scale(glm.vec3(1 / 0.8, 1 / 0.8, 1 / 0.8))
        elif event.button == 5: # scroll down
          transform = transform * glm.scale(glm.vec3(0.8, 0.8, 0.8))
      if event.type == pygame.MOUSEBUTTONUP:
        if event.button == 1:
          pressedi = None

