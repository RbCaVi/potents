import pygame
import pygamegui
import synth
import collections
import time

class Keyboard(pygamegui.Gui):
	def __init__(self):
		self.pressed = {}
		self.pressedcount = collections.defaultdict(int)

	def draw(self, surface):
		for i,j in self.pressed:
			if self.pressedcount[(i, j)] > 0:
				pygame.draw.rect(surface, (0, 0, 0), (surface.width / 2 - 50 / 2 + 75 * j, surface.height / 2 - 50 / 2 + 75 * i, 50, 50))

	def update(self):
		pass

	def mousedown(self, event):
		return False # did the click land on this object?

	def mousemoved(self, event):
		pass

	def mouseup(self, event):
		pass

	def press(self, pos):
		if pos in self.pressed:
			self.pressed[pos].expired = True
		self.pressedcount[pos] += 1
		if self.pressedcount[pos] > 0:
			i,j = pos
			steps = i * -18 + j * 10
			multiplier = 2 ** (steps / 31)
			multiplier = (3 / 2) ** j * (5 / 4) ** (-i)
			self.pressed[pos] = synth.Multiply(synth.SinePlayer(440 * multiplier), synth.LinearEnvelope(1))
			synth.players.append((0.3, self.pressed[pos]))

	def unpress(self, pos):
		self.pressedcount[pos] -= 1
		if self.pressedcount[pos] <= 0 and pos in self.pressed:
			del self.pressed[pos]

class ChordKey(pygamegui.Button):
	def __init__(self, area, keys):
		super().__init__(area)
		self.keys = keys

	def onmousedown(self):
		now = time.time()
		for i,key in enumerate(self.keys):
			presses.append((now + i * 0.03, key))
			#keyboard.press(key)

	def onmouseup(self):
		for key in self.keys:
			keyboard.unpress(key)

def onevent(event):
	if event.type == pygame.KEYDOWN:
		print(event.key)
		if event.key in keymap:
			i,j = keymap[event.key]
			gi,gj = keymap[ord('g')]
			keyboard.press((i - gi, j - gj))
	if event.type == pygame.KEYUP:
		print(event.key)
		if event.key in keymap:
			i,j = keymap[event.key]
			gi,gj = keymap[ord('g')]
			keyboard.unpress((i - gi, j - gj))

keymap = {ord(k):(i, j) for i,line in enumerate('''
`1234567890-=
 qwertyuiop[]\\
 asdfghjkl;'
 zxcvbnm,./
'''.split('\n')[1:-1]) for j,k in enumerate(line) if k != ' '}

presses = collections.deque()

class Update(pygamegui.Gui):
	# not really a gui
	def update(self):
		synth.removeexpired()
		now = time.time()
		while len(presses) > 0 and presses[0][0] < now:
			keyboard.press(presses[0][1])
			presses.popleft()

keyboard = Keyboard()

pygamegui.guis = [
	Update(),
	keyboard,
	ChordKey(pygamegui.RectArea(100, 100, 50, 50), [(0, 0), (-1, 0), (0, 1), (1, 2)]),
	ChordKey(pygamegui.RectArea(175, 100, 50, 50), [(0, -1), (-1, -1), (0, 0), (-1, 0)]),
	ChordKey(pygamegui.RectArea(100, 175, 50, 50), [(0, 0), (-1, 0), (0, 1)]),
	ChordKey(pygamegui.RectArea(175, 175, 50, 50), [(0, -1), (-1, -1), (0, 0)]),
]

pygame.init()

with synth.createstream():
	pygamegui.mainloop(onevent)