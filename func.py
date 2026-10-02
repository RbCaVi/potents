'''
let's make yet another language
explicitly manage vars within and between blocks
addvar
delvar
'''

# so my data structures
# all interlinked i dislike dealing with this

# a function is composed of multiple blocks
# each block has input variables
# each block has one control at its end
# each block has a sequence of instructions

import itertools
import collections
import frozendict

def deepfreeze(x):
	if isinstance(x, dict):
		return frozendict.frozendict((k, deepfreeze(v)) for k,v in x.items())
	elif isinstance(x, list):
		return tuple(deepfreeze(i) for i in x)
	elif isinstance(x, set):
		return frozenset(x)
	elif isinstance(x, tuple):
		return tuple(deepfreeze(i) for i in x)
	else:
		hash(x)
		return x

class Mem(collections.namedtuple('Mem', ['ctx', 'key'])):
	def new(ctx):
		return Mem(ctx, ctx.address)

	def __repr__(self):
		return f'Mem({self.key} -> {self.value})'

	@property
	def value(self):
		return self.ctx.memtable[self.key]

class Context:
	def __init__(self, address, memtable, functable):
		self.address = address
		self.memtable = {**memtable}
		self.functable = functable

	def copy(self):
		return Context(self.address, self.memtable, self.functable)

	def new(functable):
		return Context(itertools.count(0), {}, functable)

	def newmem(self):
		mem = Mem(self, next(self.address))
		_self,mem = self.set(mem, None)
		return self, mem

	def set(self, mem, val):
		self.memtable[mem.key] = val
		return self, mem

def op_add(ctx, v3, v1, v2):
	return v1 + v2, v1, v2,

def op_malloc(ctx, v):
	ctx,mem = ctx.newmem()
	return mem,

def op_setmem(ctx, v, val):
	ctx,v = ctx.set(v, val)
	return v, val,

def op_getmem(ctx, val, v):
	return v.value, v,

optable = {
	'add': op_add,
	'malloc': op_malloc,
	'setmem': op_setmem,
	'getmem': op_getmem,
}

def ctrl_if(ctx, var):
	if var:
		return 1, ctx, var
	else:
		return 0, ctx, var

controls = {
	'if': ctrl_if,
}

def call(ctx, f, args, log = lambda x: None):
	start,blocks = f
	phivars = args
	blockname = start
	while True:
		initvars,instructions,control = blocks[blockname]
		log(('enterblock', blockname, initvars))
		variables = {name:var for name,var in zip(initvars, phivars)}
		for instruction in instructions:
			match instruction:
				case ('addvar', name):
					log(('addvar', name))
					assert name not in variables
					variables[name] = None
				case ('delvar', name):
					log(('delvar', name))
					del variables[name]
				case ('op', op, args):
					log(('op', op, args))
					newvals = optable[op](ctx, *(variables[name] for name in args))
					print(args, newvals)
					for name,newval in zip(args, newvals):
						variables[name] = newval
				case ('call', func, ret, args):
					log(('call', func, ret, args))
					ctx,ret.value = call(ctx, ctx.functable[func], [variables[name] for name in args], log)
				case _:
					raise RuntimeError
		ctrl,args,jumps = control
		if ctrl == 'return':
			name, = args
			log(('return', name))
			return ctx, variables[name]
		index,ctx,*newvals = controls[ctrl](ctx, *(variables[name] for name in args))
		for name,newval in zip(args, newvals):
			variables[name] = newval
		blockname,phinames = jumps[index]
		log(('exitblock', phinames))
		phivars = [variables[name] for name in phinames]

def trace(ctx, f, args):
	log = [('call', f, '__OUT__', [f'arg{i}' for i,arg in enumerate(args)])]
	ctx1 = Context.copy(ctx)
	ctx2, out = call(ctx, ctx.functable[f], args, log.append)
	return ctx1, args, log, ctx2, out

ctx = Context.new({
	'f1': (
		'begin', # initial block
		{
			'begin': (
				['a', 'b'], # input variables
				[ # instructions
					('addvar', 'c'), # (addvar var)
					('op', 'add', ['c', 'a', 'b']), # (op name args)
					('delvar', 'a'), # (delvar var)
					('delvar', 'b'),
					('addvar', 'p'),
					('op', 'malloc', ['p']),
					('op', 'setmem', ['p', 'c']),
				],
				('return', ['p'], []) # ending control (name args jumps)
			),
		}
	),
	'f2': (
		'begin', # initial block
		{
			'begin': (
				['a', 'b'],
				[],
				('if', ['a'], [
					('false', ['b']),
					('true', ['a', 'b']),
				])
			),
			'false': (
				['a'],
				[],
				('return', ['a'], [])
			),
			'true': (
				['a', 'b'],
				[
					('addvar', 'c'),
					('op', 'add', ['c', 'a', 'b']),
					('delvar', 'a'),
					('delvar', 'b'),
					('addvar', 'p'),
					('op', 'malloc', ['p']),
					('op', 'setmem', ['p', 'c']),
				],
				('return', ['p'], [])
			),
		}
	)
})

#trace1 = trace(ctx, 'f1', [4, 6])

trace2 = trace(ctx, 'f2', [4, 6])

#trace3 = trace(ctx, 'f2', [0, 6])

#print(trace1)
print(trace2)
#print(trace3)

import pygame
import sys
import math

class Pos(collections.namedtuple('Pos', ['x', 'y'])):
	def __add__(self, that):
		x,y = self
		match that:
			case Vec(x = dx, y = dy) | (dx, dy):
				return Pos(x + dx, y + dy)
		return NotImplemented

	def __sub__(self, that):
		x,y = self
		match that:
			case Vec(x = dx, y = dy) | (dx, dy):
				return Pos(x - dx, y - dy)
			case Pos(x = x2, y = y2):
				return Vec(x - x2, y - y2)
		return NotImplemented

class Vec(collections.namedtuple('Pos', ['x', 'y'])):
	def __add__(self, that):
		x,y = self
		match that:
			case Vec(x = dx, y = dy):
				return Vec(x + dx, y + dy)
			case Pos(x = x2, y = y2):
				return Pos(x + x2, y + y2)
		return NotImplemented

	def __sub__(self, that):
		x,y = self
		match that:
			case Vec(x = dx, y = dy):
				return Vec(x - dx, y - dy)
			case Pos(x = x2, y = y2):
				return Pos(x - x2, y - y2)
		return NotImplemented

class Anchor:
	@property
	def pos(self):
		raise NotImplementedError

class AbsAnchor(Anchor):
	def __init__(self, pos):
		self.pos = pos

	@property
	def pos(self):
		return self._pos

	@pos.setter
	def pos(self, pos):
		self._pos = Pos(*pos)

class RelAnchor(Anchor):
	def __init__(self, rel, parent = None):
		self.parent = parent
		self.rel = rel

	@property
	def pos(self):
		return self.parent.pos + self.rel

class Object:
	def __init__(self, anchor):
		self.anchor = anchor

	def draw(self, surface):
		pass

	def update(self):
		pass

	@property
	def pos(self):
		return self.anchor.pos

class ContainerObject(Object):
	def __init__(self, anchor, children):
		super().__init__(anchor)
		self.children = []
		for child in children:
			self.addchild(child)

	def addchild(self, child):
		assert isinstance(child.anchor, RelAnchor)
		child.anchor.parent = self.anchor
		self.children.append(child)

	def draw(self, surface):
		for child in self.children:
			child.draw(surface)

	def update(self):
		for child in self.children:
			child.update()

class Stack(ContainerObject):
	def __init__(self, anchor, retvar, args):
		super().__init__(anchor, [])
		self.bottom = 0
		self.addchild(StackFrame(RelAnchor(Vec(0, 0)), None, None, {retvar: None, **{f'arg{i}':arg for i,arg in enumerate(args)}}))

	def pushframe(self, f, retvar, variables):
		self.bottom += self.top.height()
		self.addchild(StackFrame(RelAnchor(Vec(0, self.bottom)), f, retvar, variables))

	def popframe(self):
		self.children.pop()
		self.bottom -= self.top.height()

	@property
	def top(self):
		return self.children[-1]

class StackFrame(Object):
	def __init__(self, anchor, f, retvar, variables):
		super().__init__(anchor)
		self.f = f
		self.retvar = retvar
		self.variables = variables

	def draw(self, surface):
		ptr = self.pos
		surface.blit(font.render(self.f, True, (0, 0, 0)), ptr + (5, 5))
		pygame.draw.rect(surface, (0, 0, 255), (ptr + (10, 20), (5, 5 + len(self.variables) * 15)))
		ptr += (0, 25)
		for var,val in self.variables.items():
			surface.blit(font.render(str(var), True, (0, 0, 0)), ptr + (20, 0))
			if isinstance(val, Mem):
				rect = surface.blit(font.render(str(val.value), True, (0, 0, 0)), ptr + (100, 0))
				arrows.append((rect, val.key))
			else:
				surface.blit(font.render(str(val), True, (0, 0, 0)), ptr + (100, 0))
			ptr += (0, 15)

	def height(self):
		return 25 + 15 * len(self.variables)

pygame.init()

display = pygame.display.set_mode((640, 480), pygame.RESIZABLE)
clock = pygame.time.Clock()

font = pygame.font.Font(None, 15)

ctx,args,log,ctx2,out = trace2

loglines = iter(log)

logdisp = pygame.Surface((0, 0))

context = Context.copy(ctx)

stack = Stack(AbsAnchor(Pos(0, 0)), '__OUT__', args)

while True:
	for event in pygame.event.get():
		if event.type == pygame.QUIT:
			sys.exit()
		if event.type == pygame.MOUSEBUTTONDOWN:
			logevent = next(loglines)
			logdisp = font.render(str(logevent), True, (0, 0, 0))
			print(logevent)
			match logevent:
				case ('call', f, ret, args):
					phivals = [stack.top.variables[name] for name in args]
					stack.pushframe(f, ret, {})
				case ('enterblock', block, phivars):
					stack.top.variables = {var:val for var,val in zip(phivars, phivals)}
				case ('exitblock', phivars):
					phivals = [stack.top.variables[var] for var in phivars]
					stack.top.variables = {}
				case ('addvar', name):
					stack.top.variables[name] = None
				case ('delvar', name):
					del stack.top.variables[name]
				case ('op', name, args):
					newvals = optable[name](context, *(stack.top.variables[name] for name in args))
					for name,newval in zip(args, newvals):
						stack.top.variables[name] = newval
				case ('return', name):
					retval = stack.top.variables[name]
					retvar = stack.top.retvar
					stack.popframe()
					stack.top.variables[retvar] = retval
				case _:
					print('unrecognized')
		if event.type == pygame.MOUSEMOTION:
			pass
		if event.type == pygame.MOUSEBUTTONUP:
			pass
	display.fill((255, 255, 255))
	arrows = []
	stack.draw(display)
	y = 5
	mems = {}
	for i,val in context.memtable.items():
		rect = display.blit(font.render(str(i), True, (0, 0, 0)), (200, y))
		display.blit(font.render(str(val), True, (0, 0, 0)), (220, y))
		mems[i] = rect
		y += 15
	x = 150
	for srect,dest in arrows:
		begin = srect.midright
		end = mems[dest].midleft
		pygame.draw.line(display, (255, 0, 0), begin, (x, begin[1]), width = 2) 
		pygame.draw.line(display, (255, 0, 0), (x, begin[1]), (x, end[1]), width = 2) 
		pygame.draw.line(display, (255, 0, 0), (x, end[1]), end, width = 2)
		x += 5 
	display.blit(logdisp, (0, 0))
	pygame.display.flip()
	clock.tick(60)