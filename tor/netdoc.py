import itertools
import base64

import lib

class Line:
  def __init__(self, keyword, arguments, object_name, object_data):
    self.keyword = keyword
    self.arguments = arguments
    self.object_name = object_name
    self.object_data = object_data

@lib.generator_to_list
def parse_netdoc(netdoc):
  lines = lib.Peekable(line for line in netdoc.split('\n') if line != '')
  for line in lines:
    # parse line as a KeywordLine - keyword + spaces/tabs + arguments
    # i'm assuming i get a well formed document so i don't have to check keyword validity
    # or that whitespace is only spaces and tabs
    # or that there aren't any embedded null characters
    keyword,*arguments = line.split()
    if lines.peek().startswith('-----BEGIN '):
      line = next(lines)
      object_name = line[len('-----BEGIN '):-len('-----')]
      end_line = '-----END ' + object_name + '-----'
      object_encoded = ''.join(itertools.takewhile(lambda line: line != end_line, lines)) # the last line disappears but that's what i want anyway
      object_data = base64.b64decode(object_encoded)
    else:
      object_name = None
      object_data = None
    yield Line(keyword, arguments, object_name, object_data)

def get_line_args_optional_no_object(line_type, lines, default = None):
  # assumes lines is a Peekable
  # returns the line arguments or None
  # errors if an object is present
  if lines.peek().keyword == line_type:
    line = next(lines)
    assert line.object_name is None, f'line of type {line_type} should not have an object'
    return line.arguments
  else:
    return default

def get_line_args_no_object(line_type, lines):
  # lines is a Peekable
  # returns the line arguments
  # errors if an object is present
  check_type = lines.peek().keyword
  assert check_type == line_type, f'missing required line of type {line_type}; got {check_type}'
  line = next(lines)
  assert line.object_name is None, f'line of type {line_type} should not have an object'
  return line.arguments