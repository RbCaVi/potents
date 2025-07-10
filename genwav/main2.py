import soundgen
import numpy

def cosn(n):
  return lambda x: numpy.cos(n * x)

def sinn(n):
  return lambda x: numpy.sin(n * x)

samplerate,sound = soundgen.readwav('testing.wav')

with soundgen.setsamplerate(samplerate):
  #print('cos')
  #soundgen.writewav('testingcos.wav', soundgen.rescale(soundgen.transform(sound, soundgen.coswave)))
  #print('cos done')

  #print('cos2')
  #soundgen.writewav('testingcos2.wav', soundgen.rescale(soundgen.transform(sound, soundgen.cos2wave)))
  #print('cos2 done')

  #print('cos3')
  #soundgen.writewav('testingcos3.wav', soundgen.rescale(soundgen.transform(sound, soundgen.cos3wave)))
  #print('cos3 done')

  #print('sin')
  #soundgen.writewav('testingsin.wav', soundgen.rescale(soundgen.transform(sound, soundgen.sinwave)))
  #print('sin done')

  #print('sin2')
  #soundgen.writewav('testingsin2.wav', soundgen.rescale(soundgen.transform(sound, soundgen.sin2wave)))
  #print('sin2 done')

  #print('sin3')
  #soundgen.writewav('testingsin3.wav', soundgen.rescale(soundgen.transform(sound, soundgen.sin3wave)))
  #print('sin3 done')

  #print('tri')
  #soundgen.writewav('testingtri.wav', soundgen.rescale(soundgen.transform(sound, soundgen.triwave)))
  #print('tri done')

  #print('saw')
  #soundgen.writewav('testingsaw.wav', soundgen.rescale(soundgen.transform(sound, soundgen.sawwave)))
  #print('saw done')

  #print('sqr')
  #soundgen.writewav('testingsqr.wav', soundgen.rescale(soundgen.transform(sound, soundgen.sqrwave)))
  #print('sqr done')

  #print('wave')
  #soundgen.writewav('testingwave.wav', soundgen.rescale(soundgen.transform(sound, wavewave)))
  #print('wave done')
  
  #for i in range(10 + 1):
  #  print(f'cos - h{i}')
  #  soundgen.writewav(f'testingcos_h{i}.wav', soundgen.rescale(soundgen.transform(sound, cosn(i))))
  #  print(f'cos done - h{i}')
  #  
  #  print(f'sin - h{i}')
  #  soundgen.writewav(f'testingcos_h{i}.wav', soundgen.rescale(soundgen.transform(sound, sinn(i))))
  #  print(f'sin done - h{i}')
  
  spectrum = soundgen.spectrum(sound)
  
  for i in range(10 + 1):
    print(f'cos - h{i}')
    soundgen.writewav(f'testingcos_h{i}.wav', soundgen.rescale(soundgen.transformspectrum(spectrum, cosn(i))))
    print(f'cos done - h{i}')
    
    print(f'sin - h{i}')
    soundgen.writewav(f'testingsin_h{i}.wav', soundgen.rescale(soundgen.transformspectrum(spectrum, sinn(i))))
    print(f'sin done - h{i}')