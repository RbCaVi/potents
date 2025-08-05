import itertools
import base64

import lib

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
    yield keyword, arguments, object_name, object_data