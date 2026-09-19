# state space explorer
# graph traversal

import pygame

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
        if edgekind == 0 and nextnode in nodes and node in graph[nextnode]:
          nodes.remove(nextnode)
          tovisit.add(nextnode)
    collapsed[frozenset(group)] = {}
  for n1,n2,kind in ((n1, n2, kind) for n1,edges in graph.items() for n2,kind in edges.items()):
    if frozenset(quotient[n1]) == frozenset(quotient[n2]):
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
  (1, 1),
tuple('''
######
#    #
# oo #
#    #
######
'''.strip().split('\n')),
), nextstates)

vertices,graph = toindexes(fullgraph)

print(vertices, graph)

print(toindexes(collapse(fullgraph)))

#vertices,graph = toindexes(collapse(fullgraph))

import pggraph
pggraph.run(vertices, graph, renderstate)

vertices,graph = toindexes(collapse(fullgraph))
#pggraph.run(vertices, graph, renderstate2)