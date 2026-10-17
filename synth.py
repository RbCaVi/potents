import sounddevice
import math
import numpy

samplerate = 44100

class Player:
	def __init__(self):
		self.expired = False

	def advance(self, n):
		# returns a numpy ndarray of shape (n,)
		raise NotImplementedError

	def expired(self):
		return False

class SinePlayer(Player):
	def __init__(self, hz):
		super().__init__()
		self.w = 2 * math.pi * hz / samplerate # angular velocity
		self.T = samplerate / hz # period
		self.offset = 0

	def advance(self, n):
		data = numpy.sin((numpy.arange(n) + self.offset) * self.w)
		self.offset = (self.offset + n) % self.T
		return data[:, numpy.newaxis]

class LinearEnvelope(Player):
	def __init__(self, release):
		super().__init__()
		self.release = release * samplerate
		self.timer = 0

	def advance(self, n):
		data = numpy.clip(numpy.arange(self.release - self.timer, self.release - self.timer - n, -1) / self.release, 0, None)
		self.timer += n
		if self.timer > self.release:
			self.expired = True
		return data[:, numpy.newaxis]

class Multiply(Player):
	def __init__(self, left, right):
		super().__init__()
		self.left = left
		self.right = right

	def advance(self, n):
		data = self.left.advance(n) * self.right.advance(n)
		self.expired = self.expired or self.left.expired or self.right.expired
		return data

players = []

def mixer(indata, outdata, frames, _time, _status):
	data = numpy.zeros((frames, 2))
	for volume,player in players:
		data += player.advance(frames) * volume
	outdata[:] = numpy.clip(data, -1, 1)

def createstream():
	return sounddevice.Stream(samplerate = samplerate, channels = 2, dtype = numpy.float32, callback = mixer)

def removeexpired():
	players[:] = [x for x in players if not x[1].expired]