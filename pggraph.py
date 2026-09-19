# state space explorer
# graph traversal

import random
import pygame
import pygame.locals
from OpenGL.GL import *
import sys
import math

import numpy
from ctypes import *

import contextlib

from pyglm import glm

pygame.init()

# request a 3.1 opengl i guess
pygame.display.gl_set_attribute(pygame.GL_CONTEXT_MAJOR_VERSION, 3)
pygame.display.gl_set_attribute(pygame.GL_CONTEXT_MINOR_VERSION, 1)
pygame.display.gl_set_attribute(pygame.GL_CONTEXT_PROFILE_MASK, pygame.GL_CONTEXT_PROFILE_CORE)

# spring layout parameters
cs = 0.02
l = 0.1
cr = 0.005

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

  return program

# set uniform variables
def setfloat(program, name, f):
  uniform = glGetUniformLocation(program, name)
  glUniform1f(uniform, f)

def setint(program, name, i):
  uniform = glGetUniformLocation(program, name)
  glUniform1i(uniform, i)

def setmat4(program, name, m):
  uniform = glGetUniformLocation(program, name)
  glUniformMatrix4fv(uniform, 1, False, numpy.array(m).flatten())

# create an array buffer
# pre "set" the stride (floats per vertex / instance)
# because i think usually you would want to have
# all the attributes stored in an array have the same stride
# returns a handle object that can be used in loadFloatArray and applyvd / applyvdinstanced
def createArray(size): # size is the number of floats in a vertex
  handle = glGenBuffers(1)
  return handle, size

# load a 2d numpy array of floats into an array buffer
# it must have the same number of floats per vertex
def loadFloatArray(handle, data, kind = GL_STATIC_DRAW):
  count,size = data.shape
  assert handle[1] == size
  glBindBuffer(GL_ARRAY_BUFFER, handle[0])
  glBufferData(GL_ARRAY_BUFFER, count * handle[1] * sizeof(c_float), data.flatten(), kind)

# set a vertex attribute
# returns an attribute object that can be used in enableAttr / disableAttr and glAttr
def applyvd(program, handle, name, size, offset):
  attr = glGetAttribLocation(program, name)
  glBindBuffer(GL_ARRAY_BUFFER, handle[0])
  glVertexAttribPointer(attr, size, GL_FLOAT, False, handle[1] * sizeof(c_float), c_void_p(offset * sizeof(c_float)))
  return handle, attr

# set an instance attribute
# returns an attribute object that can be used in enableAttr / disableAttr and glAttr
def applyvdinstanced(program, handle, name, size, offset):
  handle,attr = applyvd(program, handle, name, size, offset)
  glVertexAttribDivisor(attr, 1)
  return handle, attr

# whatever glEnableVertexAttribArray does
def enableAttr(attr):
  glBindBuffer(GL_ARRAY_BUFFER, attr[0][0])
  glEnableVertexAttribArray(attr[1])

# whatever glDisableVertexAttribArray does
def disableAttr(attr):
  glBindBuffer(GL_ARRAY_BUFFER, attr[0][0])
  glDisableVertexAttribArray(attr[1])

# enable a vertex / instance attribute inside a with block
@contextlib.contextmanager
def glAttr(attr):
  enableAttr(attr)
  yield
  disableAttr(attr)

# the shader and geometry for the graph nodes
nodeverts = numpy.array([
  [-0.1, -0.1],
  [-0.1,  0.1],
  [ 0.1,  0.1],
  [ 0.1, -0.1],
  [-0.1, -0.1],
  [ 0.1,  0.1],
], dtype = numpy.float32)

nodevert = """
#version 120

uniform mat4 transform; // camera transform

attribute vec2 coord; // node geometry
attribute vec3 off; // position of node

void main() {
  // draw the node with a size and orientation unaffected by the transform
  gl_Position = vec4(off, 1.0) * transform + vec4(coord * 0.1, 0, 0);
}
"""

nodefrag = """
#version 120

void main() {
  gl_FragData[0] = vec4(1.0, 0.0, 0.0, 1.0);
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
  vec2 dir = normalize((vec4(end - start, 0) * transform).xy);
  vec2 perp = vec2(dir.y, -dir.x);
  // stretch the arrow to keep the arrowhead the same size
  if (coord.x < 0.5) {
    gl_Position = vec4(start.xyz, 1.0) * transform + vec4((dir * coord.x + perp * coord.y) * 0.2, 0, 0);
  } else {
    gl_Position = vec4(end.xyz, 1.0) * transform + vec4((dir * (coord.x - 1) + perp * coord.y) * 0.2, 0, 0);
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

def run(vertices, graph, renderstate):
  # create a mask of which edges have attraction forces applied
  # and a list of edges
  mask = numpy.full((len(graph), len(graph), 3), True, dtype = numpy.bool)
  edges = []
  for i in graph:
    for j in graph[i]:
      if i == j:
        continue
      mask[i, j] = mask[j, i] = False, False, False
      edges.append((i, j, graph[i][j]))

  edges = numpy.array(edges, dtype = numpy.int32).reshape((len(edges), 3))

  # initialize the node positions
  pos = numpy.array([(random.uniform(-1, 1), random.uniform(-1, 1), random.uniform(-1, 1)) for k in graph], dtype = numpy.float32)

  # initialize the window
  size = (600, 600)
  pygame.display.set_mode(size, pygame.locals.DOUBLEBUF | pygame.locals.OPENGL)

  glClearColor(0.0, 0.0, 0.0, 0.0)

  # compile the programs and set up their geometry and attributes
  nodeprogram = compileprogram(nodevert, nodefrag, {'coord': 0, 'off': 1})
  arrowprogram = compileprogram(arrowvert, arrowfrag, {'coord': 2, 'start': 3, 'end': 4, 'edgekind': 5})
  bgprogram = compileprogram(bgvert, bgfrag, {'coord': 6, 'img': 7})

  glUseProgram(nodeprogram)
  verts = createArray(2)
  loadFloatArray(verts, nodeverts)
  coordattr = applyvd(nodeprogram, verts, "coord", 2, 0)

  poss = createArray(3)
  posattr = applyvdinstanced(nodeprogram, poss, "off", 3, 0)

  glUseProgram(arrowprogram)
  verts2 = createArray(2)
  loadFloatArray(verts2, arrowverts)
  coordattr2 = applyvd(arrowprogram, verts2, "coord", 2, 0)

  edgedata = createArray(7)
  startattr = applyvdinstanced(arrowprogram, edgedata, "start", 3, 0)
  endattr = applyvdinstanced(arrowprogram, edgedata, "end", 3, 3)
  edgekindattr = applyvdinstanced(arrowprogram, edgedata, "edgekind", 1, 6)

  glUseProgram(bgprogram)
  verts3 = createArray(2)
  loadFloatArray(verts3, bgverts)
  coordattr3 = applyvd(bgprogram, verts3, "coord", 2, 0)

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
    glUseProgram(bgprogram)
    setint(bgprogram, 'img', screentexture)

    glEnable(GL_TEXTURE_2D)
    with glAttr(coordattr3):
      glDrawArrays(GL_TRIANGLES, 0, 6)
    glDisable(GL_TEXTURE_2D)

    # draw the nodes
    glUseProgram(nodeprogram)
    loadFloatArray(poss, pos, GL_DYNAMIC_DRAW)
    setmat4(nodeprogram, 'transform', transform)

    with glAttr(coordattr), glAttr(posattr):
      glDrawArraysInstanced(GL_TRIANGLES, 0, 6, len(pos))

    # draw the edges
    glUseProgram(arrowprogram)
    loadFloatArray(edgedata, numpy.concatenate((pos[edges[:, 0]], pos[edges[:, 1]], edges[:, 2, numpy.newaxis].astype(numpy.float32)), axis = 1), GL_DYNAMIC_DRAW)
    setmat4(arrowprogram, 'transform', transform)

    with glAttr(coordattr2), glAttr(startattr), glAttr(endattr), glAttr(edgekindattr):
      glDrawArraysInstanced(GL_LINES, 0, 6, len(edges))

    # refresh the display and wait for framerate
    pygame.display.flip()
    pygame.time.wait(10)
    
    # save the position of the currently dragged node
    if pressedi is not None:
      if pressedi == -1:
        pass
      else:
        savedpos = pos[pressedi].copy()

    # node physics
    disps = pos[numpy.newaxis, :, :] - pos[:, numpy.newaxis, :] # displacement
    dist2s = numpy.sum(disps ** 2, axis = 2) # distance squared
    dists = numpy.sqrt(dist2s) # distance
    dirs = disps / dists[:, :, numpy.newaxis] # unit vector of displacement
    
    # attraction proportional to log(distance / length)
    fattrs = numpy.ma.MaskedArray(-numpy.clip(numpy.nan_to_num(cs * numpy.log(dists[:, :, numpy.newaxis] / l), -1, 1) * dirs), mask).filled(0)
    # repulsion proportional to the inverse square
    freps = numpy.nan_to_num(cr / dist2s[:, :, numpy.newaxis] * dirs)
    
    # despite being labelled "force", they are actually velocity
    fs = fattrs + freps
    pos += fs.sum(0) # sum over axis 0

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
        pos[pressedi] = savedpos + (glm.inverse(transform) * glm.vec4(dmpos, 0, 0)).xyz

    if pygame.mouse.get_pressed()[2]: # right mouse
      # cross mouse movement with 0 0 1
      # to get a rotation axis perpendicular to mouse movement
      # then the magnitude is the sin of some angle idk
      axis = glm.cross(glm.normalize(glm.vec3(dmpos, 1)), glm.vec3(0, 0, 1))
      mag = glm.length(axis)
      if mag > 0.0000001: # idk some epsilon
        angle = math.asin(mag)
        transform = glm.rotate(angle, axis) * transform

    # find the closest node to the mouse
    mind = math.inf
    mini = None
    for i,npos in enumerate(pos):
      npost = transform * glm.vec4(npos, 1)
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

