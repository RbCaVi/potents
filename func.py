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

class Mem(collections.namedtuple('Mem', ['ctx', 'key'])):
	def new(ctx):
		mem = Mem(ctx, next(ctx.address))
		return mem

	def __repr__(self):
		return f'Mem({self.key} -> {self.value})'

	@property
	def value(self):
		return self.ctx.memtable[self.key]

class Context(collections.namedtuple('Context', ['address', 'memtable'])):
	def new():
		return Context(itertools.count(), frozendict.frozendict())

	def newmem(self):
		mem = Mem.new(self)
		ctx,mem = self.set(mem, None)
		return ctx, mem

	def set(self, mem, val):
		ctx = self._replace(memtable = self.memtable | {mem.key: val})
		return ctx, mem._replace(ctx = ctx)

def op_add(ctx, v3, v1, v2):
	return ctx, v1 + v2, v1, v2,

def op_malloc(ctx, v):
	ctx,mem = ctx.newmem()
	return ctx, mem,

def op_setmem(ctx, v, val):
	ctx,v = ctx.set(v, val)
	return ctx, v, val,

def op_getmem(ctx, val, v):
	return ctx, v.value, v,

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
					ctx,*newvals = optable[op](ctx, *(variables[name] for name in args))
					for name,newval in zip(args, newvals):
						variables[name] = newval
				case ('call', func, ret, args):
					log(('call', func, ret, args))
					ctx,ret.value = call(ctx, func, args, log)
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
	log = []
	ctx2, out = call(ctx, f, args, log.append)
	return ctx, args, out, log

f1 = (
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
)

f2 = (
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

trace1 = trace(Context.new(), f1, [4, 6])

trace2 = trace(Context.new(), f2, [4, 6])

trace3 = trace(Context.new(), f2, [0, 6])

print(trace1)
print(trace2)
print(trace3)