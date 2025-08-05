class Peekable:
  def __init__(self, it):
    self.it = iter(it)
    self.buffer = []
  
  def __iter__(self):
    return self
  
  def __next__(self):
    if len(self.buffer) == 1:
      return self.buffer.pop()
    else:
      return next(self.it)
  
  def peek(self):
    if len(self.buffer) == 0:
      self.buffer.append(next(self.it))
    return self.buffer[0]

# convert a function that returns a generator to one that returns a list
def generator_to_list(f):
  return lambda *args, **kwargs: [*f(*args, **kwargs)]

def get_line_args_optional_no_object(line_type, lines, default = None):
  # assumes lines is a Peekable
  # returns the line arguments or None
  # errors if an object is present
  if lines.peek()[0] == line_type:
    line = next(lines)
    assert line[2] is None, f'line of type {line_type} should not have an object'
    return line[1]
  else:
    return default

def get_line_args_no_object(line_type, lines):
  # lines is a Peekable
  # returns the line arguments
  # errors if an object is present
  check_type = lines.peek()[0]
  assert check_type == line_type, f'missing required line of type {line_type}; got {check_type}'
  line = next(lines)
  assert line[2] is None, f'line of type {line_type} should not have an object'
  return line[1]

# convert a list of 'key=value' strings to a dictionary
def params_to_dict(params):
  if params is None:
    return None
  split = [kv.split('=') for kv in params]
  out = {k:v for k,v in split}
  assert len(out) == len(split), 'duplicate key :('
  return out