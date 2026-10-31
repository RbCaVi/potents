import pygame
import sys

pygame.font.init()
font = pygame.font.SysFont('', 25)

class Node:
	def __init__(self, x, y, val):
		self.x = x
		self.y = y
		self.dx = x
		self.dy = y
		self.val = val
		self.outline = (0, 0, 0)
		self.linecolor = (0, 0, 0)

	def display1(self, surface):
		x,y = self.pos()
		pygame.draw.rect(surface, (255, 255, 255), (x - 15, y - 15, 30, 30))
		pygame.draw.rect(surface, self.outline, (x - 15, y - 15, 30, 30), width = 1)

	def display2(self, surface):
		x,y = self.dpos()
		s = font.render(str(self.val), True, (0, 0, 0))
		surface.blit(s,(x - s.height / 2, y - s.width / 2))

	def pos(self):
		return self.x * 40 + 320, self.y * 40 + 50

	def dpos(self):
		return self.dx * 40 + 320, self.dy * 40 + 50

class Heap:
	def __init__(self, items, depth, maxheap = True):
		self.depth = depth
		self.maxheap = maxheap
		w = 2 ** depth
		if len(items) == 0:
			self.nodes = []
			return
		self.nodes = [Node(0, 0, items[0])]
		for i,v in enumerate(items[1:]):
			i = i + 1
			right = (i - 1) & 1
			p = self.nodes[(i - 1) // 2]
			w = 2 ** (depth - p.y) / 4
			self.nodes.append(Node(p.x + (w / 2 if right else -w / 2), p.y + 1, v))

	def display(self):
		if len(self.nodes) == 0:
			return
		for i,n in enumerate(self.nodes[1:]):
			i = i + 1
			pi = (i - 1) // 2
			p = self.nodes[(i - 1) // 2]
			pygame.draw.line(display, n.linecolor, n.pos(), p.pos(), width = 3)
		self.nodes[0].display1(display)
		for i,n in enumerate(self.nodes[1:]):
			n.display1(display)
		self.nodes[0].display2(display)
		for i,n in enumerate(self.nodes[1:]):
			n.display2(display)

	def maindraw(self):
		for event in pygame.event.get():
			if event.type == pygame.QUIT:
				sys.exit()
		display.fill((255, 255, 255))
		self.display()
		pygame.display.flip()
		clock.tick(60)

	def waitclick(self):
		while True:
			for event in pygame.event.get():
				if event.type == pygame.QUIT:
					sys.exit()
				if event.type == pygame.MOUSEBUTTONDOWN:
					return
			display.fill((255, 255, 255))
			self.display()
			pygame.display.flip()
			clock.tick(60)

	def swap(self, i1, i2, speed = 0.03):
		n1 = self.nodes[i1]
		n2 = self.nodes[i2]
		n1p = n1.x, n1.y
		n2p = n2.x, n2.y
		progress = 0
		while progress < 1:
			progress += speed
			n1.dx,n1.dy = interp(progress, n1p, n2p)
			n2.dx,n2.dy = interp(progress, n2p, n1p)
			self.maindraw()
		self.nodes[i1] = n2
		self.nodes[i2] = n1
		n1.x,n1.y = n2p
		n2.x,n2.y = n1p

	def wait(self, frames):
		for i in range(frames):
			self.maindraw()

	def flash(self, highlight, highlightcolor, frames, repeat):
		colors = ([highlightcolor] * frames + [(0, 0, 0)] * frames) * repeat
		for color in colors:
			self.nodes[highlight].linecolor = color
			self.maindraw()

	def flash2(self, highlight1, highlight2, highlightcolor, frames, repeat):
		colors = ([highlightcolor] * frames + [(0, 0, 0)] * frames) * repeat
		for color in colors:
			self.nodes[highlight1].linecolor = color
			self.nodes[highlight2].linecolor = color
			self.maindraw()

	def append(self, value):
		if len(self.nodes) == 0:
			self.nodes.append(Node(0, 0, value))
			return
		i = len(self.nodes)
		right = (i - 1) & 1
		p = self.nodes[(i - 1) // 2]
		w = 2 ** (self.depth - p.y) / 4
		self.nodes.append(Node(p.x + (w / 2 if right else -w / 2), p.y + 1, value))

	def appendheapify(self, value):
		i = len(self.nodes)
		self.append(value)
		self.heapifyup(i)

	def heapifyup(self, i):
		if i != 0:
			n = self.nodes[i]
			p = self.nodes[(i - 1) // 2]
			if self.unordered(n.val, p.val):
				self.flash(i, (255, 0, 0), 5, 4)
				self.wait(10)
				self.swap(i, (i - 1) // 2)
				self.heapifyup((i - 1) // 2)
			else:
				self.flash(i, (0, 255, 0), 5, 4)
		else:
			self.flash(i, (0, 0, 0), 5, 4)

	def pop(self, speed = 0.03):
		n1 = self.nodes[0]
		n2 = self.nodes[-1]
		n1p = n1.x, n1.y
		n2p = n2.x, n2.y
		n2.x,n2.y = n1p
		progress = 0
		while progress < 1:
			progress += speed
			n1.dx,n1.dy = interp(progress, n1p, (n1p[0] + 1, n1p[1]))
			n2.dx,n2.dy = interp(progress, n2p, n1p)
			self.maindraw()
		n = self.nodes[0]
		self.nodes.pop()
		self.nodes[0] = n2
		for i in range(20):
			for event in pygame.event.get():
				if event.type == pygame.QUIT:
					sys.exit()
			display.fill((255, 255, 255))
			self.display()
			n.display2(display)
			pygame.display.flip()
			clock.tick(60)

	def heapifydown(self, i):
		n = self.nodes[i]
		cli = 2 * i + 1
		cri = 2 * i + 2
		if cli >= len(self.nodes):
			return
		cl = self.nodes[cli]
		if cri >= len(self.nodes):
			if self.unordered(cl.val, n.val):
				self.flash(cli, (255, 0, 0), 5, 4)
				self.wait(10)
				self.swap(cli, i)
				self.heapifydown(cli)
			else:
				self.flash(cli, (0, 255, 0), 5, 4)
			return
		cr = self.nodes[cri]
		if self.unordered(cl.val, n.val) and self.unordered(cl.val,cr.val):
			self.flash(cli, (255, 0, 0), 5, 4)
			self.wait(10)
			self.swap(cli, i)
			self.heapifydown(cli)
		elif self.unordered(cr.val, n.val) and self.unordered(cr.val,cl.val):
			self.flash(cri, (255, 0, 0), 5, 4)
			self.wait(10)
			self.swap(cri, i)
			self.heapifydown(cri)
		else:
			self.flash2(cli, cri, (0, 255, 0), 5, 4)

	def popheapify(self):
		self.pop()
		self.wait(10)
		self.heapifydown(0)

	def unordered(self, val, parent):
		if self.maxheap:
			return val > parent
		else:
			return val < parent

def lerp(t, x1, x2):
	return (1 - t) * x1 + t * x2

def interp(t, p1, p2):
	x1,y1 = p1
	x2,y2 = p2
	return (lerp(t, x1, x2), lerp(t, y1, y2))

pygame.init()

display = pygame.display.set_mode((640, 480), pygame.RESIZABLE)
clock = pygame.time.Clock()

heap = Heap([50, 30, 40, 10, 20], 3, True)
heap.waitclick()
heap.appendheapify(45)

heap.waitclick()

heap = Heap([90, 80, 70, 40, 60, 30, 50], 3, True)
heap.wait(60)
heap.popheapify()

heap.waitclick()

heap = Heap([8, 10, 12, 14, 15], 3, False)
heap.wait(60)
heap.appendheapify(5)

heap.waitclick()

heap = Heap([4, 6, 8, 10, 12, 14, 16], 3, False)
heap.wait(60)
heap.popheapify()

heap.waitclick()

heap = Heap([], 4, True)
heap.wait(60)
for x in [25, 40, 35, 50, 10, 45, 60, 20]:
    heap.appendheapify(x)
    heap.wait(20)

heap.waitclick()

heap = Heap([], 4, False)
heap.wait(60)
for x in [90, 70, 80, 60, 50, 40, 30, 20]:
    heap.appendheapify(x)
    heap.wait(20)

heap.waitclick()

sys.exit()