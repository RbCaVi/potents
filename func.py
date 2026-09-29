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
					ctx,ret.value = call(ctx, ctx.functable[func], args, log)
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
	log = [('call', f, '__OUT__', args)]
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

pygame.init()

display = pygame.display.set_mode((640, 480), pygame.RESIZABLE)
clock = pygame.time.Clock()

font = pygame.font.Font(None, 15)

ctx,args,log,ctx2,out = trace2

loglines = iter(log)

logdisp = pygame.Surface((0, 0))

stack = [[None, None, {'__OUT__': None}]]

context = Context.copy(ctx)

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
					stack.append([f, ret, {}])
					phivals = args
				case ('enterblock', block, phivars):
					stack[-1][2] = {var:val for var,val in zip(phivars, phivals)}
				case ('exitblock', phivars):
					phivals = [stack[-1][2][var] for var in phivars]
				case ('addvar', name):
					stack[-1][2][name] = None
				case ('delvar', name):
					del stack[-1][2][name]
				case ('op', name, args):
					newvals = optable[name](context, *(stack[-1][2][name] for name in args))
					for name,newval in zip(args, newvals):
						stack[-1][2][name] = newval
				case ('return', name):
					retval = stack[-1][2][name]
					_f,retvar,_variables = stack.pop()
					stack[-1][2][retvar] = retval
				case _:
					print('unrecognized')
		if event.type == pygame.MOUSEMOTION:
			pass
		if event.type == pygame.MOUSEBUTTONUP:
			pass
	display.fill((255, 255, 255))
	y = 5
	arrows = []
	for frame in stack[0:]:
		f,_,variables = frame
		display.blit(font.render(f, True, (0, 0, 0)), (5, y))
		y += 15
		pygame.draw.rect(display, (0, 0, 255), (10, y, 5, 5 + len(variables) * 15))
		y += 5
		for var,val in variables.items():
			display.blit(font.render(str(var), True, (0, 0, 0)), (20, y))
			if isinstance(val, Mem):
				rect = display.blit(font.render(str(val.value), True, (0, 0, 0)), (100, y))
				arrows.append((rect, val.key))
			else:
				display.blit(font.render(str(val), True, (0, 0, 0)), (100, y))
			y += 15
		y += 5
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