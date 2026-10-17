import pygame
import sys

# simple "gui" framework


class Gui:
	def draw(self, surface):
		pass

	def update(self):
		pass

	def mousedown(self, event):
		return False # did the click land on this object?

	def mousemoved(self, event):
		pass

	def mouseup(self, event):
		pass

class Button(Gui):
	def __init__(self, area):
		self.pressed = False
		self.area = area

	def draw(self, surface):
		if self.pressed:
			color = (0, 0, 0)
		else:
			color = (150, 150, 150)
		self.area.draw(surface, color)

	def mousedown(self, event):
		if event.button == 1:
			if self.area.collidepoint(event.pos):
				self.pressed = True
				self.onmousedown()
				return True

	def onmousedown(self):
		pass

	def mouseup(self, event):
		if event.button == 1:
			if self.pressed:
				self.onmouseup()
			self.pressed = False

	def onmouseup(self):
		pass

class Area:
	def collidepoint(self, point):
		raise NotImplementedError

	def draw(self, surface, color):
		raise NotImplementedError

class CircleArea(Area):
	def __init__(self, x, y, r):
		self.x = x
		self.y = y
		self.r = r

	def collidepoint(self, point):
		x,y = point
		dx = self.x - x
		dy = self.y - y
		return dx ** 2 + dy ** 2 < self.r ** 2

	def draw(self, surface, color):
		pygame.draw.circle(surface, color, (self.x, self.y), self.r)

class RectArea(Area):
	def __init__(self, *args):
		self.rect = pygame.rect.Rect(*args)

	def collidepoint(self, point):
		return self.rect.collidepoint(point)

	def draw(self, surface, color):
		pygame.draw.rect(surface, color, self.rect)

def mainloop(onevent = lambda event: None):
	display = pygame.display.set_mode((640, 480), pygame.RESIZABLE)
	clock = pygame.time.Clock()

	touched = None
	
	while True:
		for event in pygame.event.get():
			if event.type == pygame.QUIT:
				sys.exit()
			elif event.type == pygame.MOUSEBUTTONDOWN:
				for gui in guis:
					if gui.mousedown(event):
						touched = gui
						break
			elif event.type == pygame.MOUSEMOTION:
				if touched is not None:
					touched.mousemoved(event)
			elif event.type == pygame.MOUSEBUTTONUP:
				if touched is not None:
					touched.mouseup(event)
					touched = None
			else:
				onevent(event)
		for gui in guis:
			gui.update()
		display.fill((255, 255, 255))
		for gui in guis:
			gui.draw(display)
		pygame.display.flip()
		clock.tick(60)