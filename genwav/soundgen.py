import wave
import struct
import math
import itertools
import contextlib
import collections
import numpy.fft
#import PIL.Image

from numpy import sin, cos, pi

coswave = cos

# these two are copied from itertools documentation
def batched(iterable, n):
  iterator = iter(iterable)
  while batch := tuple(itertools.islice(iterator, n)):
    yield batch

def sliding_window(iterable, n):
    iterator = iter(iterable)
    window = collections.deque(itertools.islice(iterator, n - 1), maxlen=n)
    for x in iterator:
        window.append(x)
        yield tuple(window)

samplerate = None

@contextlib.contextmanager
def setsamplerate(newsamplerate):
  global samplerate
  savedsamplerate = samplerate
  samplerate = newsamplerate
  yield
  samplerate = savedsamplerate

def withsamplecount(f):
  def f2(duration, *args):
    samplecount = int(duration * samplerate)
    return f(samplecount, *args)
  return f2

def withsamplecountperiod(f):
  def f2(duration, frequency, *args):
    samplecount = int(duration * samplerate)
    period = samplerate / frequency
    return f(samplecount, period, *args)
  return f2

def withsamplecountw(f):
  def f2(duration, frequency, *args):
    samplecount = int(duration * samplerate)
    w = 2 * pi * frequency / samplerate
    return f(samplecount, w, *args)
  return f2

@withsamplecountw
def sine(samplecount, w):
  return sin(numpy.arange(samplecount) * w)

@withsamplecountperiod
def saw(samplecount, period):
  return ((numpy.arange(samplecount) % period) / period) * 2 - 1

def sawwave(x):
  period = 2 * pi
  x -= period / 2
  return ((x % period) / period) * 2 - 1

@withsamplecountperiod
def square(samplecount, period):
  i = numpy.arange(samplecount)
  return numpy.where(i % period > period / 2, 1, -1)

def sqrwave(x):
  period = 2 * pi
  x += period / 4
  return numpy.where(x % period > period / 2, 1, -1)

def cwave(x):
  return numpy.ones_like(x)

def cos2wave(x):
  return cos(2 * x)

def cos3wave(x):
  return cos(3 * x)

@withsamplecountperiod
def triangle(samplecount, period):
  return numpy.abs(((numpy.arange(samplecount) % period) / period) * 2 - 1) * 2 - 1

def triwave(x):
  period = 2 * pi
  return numpy.abs(((x % period) / period) * 2 - 1) * 2 - 1

@withsamplecount
def silence(samplecount):
  return numpy.zeros(samplecount)

@withsamplecountw
def fouriersyn(samplecount, w, coeff):
  l, = numpy.shape(coeff)
  coeff = numpy.reshape(coeff, (l, 1))
  i = numpy.reshape(numpy.arange(l), (l, 1))
  cc = numpy.real(coeff)
  sc = numpy.imag(coeff)
  x = numpy.arange(samplecount)
  return numpy.sum(cc * cos(x * i * w), 0) + numpy.sum(sc * sin(x * i * w), 0)

@withsamplecountw
def sigmasyn(samplecount, w, coeff, strength):
  # https://en.wikipedia.org/wiki/Sigma_approximation
  # i feel so sigma
  l, = numpy.shape(coeff)
  coeff = numpy.reshape(coeff, (l, 1))
  i = numpy.reshape(numpy.arange(l), (l, 1))
  pik_m = (pi * i / l) - 0.0000001 # l = m : the indexes go up to l - 1
  sigma = (sin(pik_m) / pik_m) ** strength
  coeff = coeff * sigma
  cc = numpy.real(coeff)
  sc = numpy.imag(coeff)
  x = numpy.arange(samplecount)
  return numpy.sum(cc * cos(x * i * w), 0) + numpy.sum(sc * sin(x * i * w), 0)

def transform2(sound, f):
  l = len(sound) - 256 + 1
  l -= l % 32
  out = numpy.empty(l)
  freqgrid = numpy.arange(256)
  for i in range(0, l, 32):
    phase = i * 2 * pi / 256
    window = sound[i:i + 256]
    spectrum = numpy.fft.fft(window)
    timegrid = numpy.reshape(numpy.arange(32), (32, 1)) + i
    grid = timegrid * freqgrid * 2 * pi / 256
    out[i:i + 32] = numpy.mean(numpy.abs(spectrum) * f(grid), 1)[0:32]
  return out

def transform(sound, f):
  l = len(sound) - 256 + 1
  l -= l % 32
  out = numpy.empty(l)
  x = []
  timegrid = numpy.reshape(numpy.arange(256), (256, 1))
  freqgrid = numpy.arange(256)
  grid = timegrid * freqgrid * 2 * pi / 256
  for i in range(0, l, 32):
    phase = i * 2 * pi / 256
    window = sound[i:i + 256]
    spectrum = numpy.fft.fft(window)
    j = numpy.reshape(numpy.arange(256), (256, 1))
    out[i:i + 32] = numpy.mean(numpy.abs(spectrum) * f(grid + numpy.angle(spectrum)), 1)[0:32]
    #PIL.Image.fromarray(numpy.mean(numpy.abs(spectrum) * f((grid + i) * 2 * pi / 256 - numpy.angle(spectrum)), 1) * 80 + 128).show()
    #PIL.Image.fromarray(numpy.mean(numpy.abs(spectrum) * f((grid + i) * 2 * pi / 256 - numpy.angle(spectrum)), 1) * 80 + 128).show()
    #PIL.Image.fromarray(numpy.abs(spectrum)).show()
    #PIL.Image.fromarray(numpy.abs(spectrum) * f((gridx * 2 * pi / 256) * gridy - numpy.angle(spectrum)) + 128).show()
    #PIL.Image.fromarray(numpy.abs(spectrum) * f((gridy + i) * gridx * 2 * pi / 256) + 128).show()
    #PIL.Image.fromarray(numpy.abs(spectrum) * f((gridx * 2 * pi / 256 + phase) * gridy) + 128).show()
    #PIL.Image.fromarray(numpy.abs(spectrum) * f((gridx * 2 * pi / 256 + numpy.angle(spectrum)) * gridy) + 128).show()
    #PIL.Image.fromarray(numpy.mean(numpy.abs(spectrum) * f((gridy + i) * gridx * 2 * pi / 256), 1) * 100 + 128).show()
    #PIL.Image.fromarray(window * 100 + 128).show()
    #assert False
    #x.append(numpy.abs(spectrum) * f(phase * numpy.arange(256)))
    #x.append(numpy.abs(spectrum))
    #x.append(window * 100)
  #x = numpy.array(x)
  #PIL.Image.fromarray(numpy.uint8(x + 128)).show()
  return out

def triadditive(harmonics):
  weights = []
  for harmonic in range(harmonics + 1):
    weight = 0
    if harmonic % 2 == 1:
      weight = 1j / (harmonic ** 2)
    if harmonic % 4 == 3:
      weight = -weight
    weights.append(weight)
  return weights

def sqradditive(harmonics):
  weights = []
  for harmonic in range(harmonics + 1):
    weight = 0
    if harmonic % 2 == 1:
      weight = 1j / harmonic
    weights.append(weight)
  return weights

def sawadditive(harmonics):
  weights = []
  for harmonic in range(harmonics + 1):
    weight = 0
    if harmonic > 0:
      weight = 1j / harmonic
    if harmonic % 2 == 0:
      weight = -weight
    weights.append(weight)
  return weights

def adjust(sound):
  # scale a sound so its samples range from -1 to +1
  top = numpy.max(sound)
  bottom = numpy.min(sound)
  return (sound - bottom) / (top - bottom) * 2 - 1

def highestharmonic(basefrequency):
  return floor(samplerate / basefrequency)

def writewav(file, sound):
  with wave.open(file, 'wb') as f:
    f.setnchannels(1)
    f.setsampwidth(2)
    f.setframerate(samplerate)
    for samples in batched(sound, 1000):
      f.writeframes(b''.join(struct.pack('h', int(32767 * sample)) for sample in samples))