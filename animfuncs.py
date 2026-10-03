import weakref
import threading
import contextlib

objs = weakref.WeakValueDictionary()
anims = weakref.WeakValueDictionary()

def addObject(obj):
	objs[id(obj)] = obj

def addAnim(anim):
	anims[id(anim)] = anim

def createFrame(pos):
	pass

def createInterp(start, end):
	pass

animlock = threading.Lock() # animations are being updated
renderlock = threading.Lock() # animations are running
def awaitAnim():
	animlock.release()
	renderlock.acquire()
	renderlock.release()
	animlock.acquire()

# try to acquire the lock every frame
# if it is held, update animations
# unlock the renderlock momentarily after all animations are complete

stack = None

class Stack:
	chldren: list[Frame]

	@property
	def top(self):
		return self.children[-1]

	def push(self, frame):
		pass

	def pop(self):
		pass
	

class Frame(Object):
	variables: dict[str, Variable]
	anchor: Anchor

	def addvar(self, name):
		pass

	def draw(self):
		pass

class Variable:
	anchor: Anchor
	value: Any

class Anim:
	def update(self):
		pass

def op_add(out, a, b):
	pass

def op_malloc(ptr):
	pass

def op_setmem(ptr, x):
	pass
