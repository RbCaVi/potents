import pygame
import sys
import math
import threading
import animfuncs

pygame.init()

display = pygame.display.set_mode((640, 480), pygame.RESIZABLE)
clock = pygame.time.Clock()

def animthread():
	animfuncs.animlock.acquire()
	import out.generated_anim

animfuncs.renderlock.acquire()

while True:
	for event in pygame.event.get():
		if event.type == pygame.QUIT:
			sys.exit()
	if animfuncs.animlock.locked() or animfuncs.animlock.acquire(False):
		pass # update animations
		if True: # animations are completed
			animfuncs.animlock.release()
			animfuncs.renderlock.release()
			animfuncs.renderlock.acquire()
	display.fill((255, 255, 255))
	for obj in objs.values():
		obj.draw()
	pygame.display.flip()
	clock.tick(60)