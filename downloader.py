import http.server
import os
import urllib.parse

hostname = '0.0.0.0'
port = 9998

content = b'''
<!doctype html>
<html>
  <head></head>
  <body>
    {}
  </body>
</html>
'''

class FileDownloader(http.server.BaseHTTPRequestHandler):
  def do_GET(self):
    if self.path == '/':
      self.send_response(200)
      self.end_headers()
      links = '<br>\n'.join([f'''    <a href = '/files/{urllib.parse.quote(file := os.path.join(dirpath, filename))}'>{file}</a>''' for (dirpath, dirs, files) in os.walk(os.curdir) for filename in files])
      self.wfile.write(f'''
<!doctype html>
<html>
  <head></head>
  <body>
{links}
  </body>
</html>
'''.encode('utf-8'))
    if self.path.startswith('/files/'):
      filename = urllib.parse.unquote(os.path.relpath(self.path, start = '/files'))
      if os.path.exists(filename):
        self.send_response(200)
        self.end_headers()
        with open(filename, 'rb') as file:
          while len(chunk := file.read()) > 0:
            self.wfile.write(chunk)
      else:
        self.send_response(404)
        self.end_headers()

if __name__ == '__main__':
  server = http.server.ThreadingHTTPServer((hostname, port), FileDownloader)
  print(f'server at http://{hostname}:{port}')
  
  try:
    server.serve_forever()
  except KeyboardInterrupt:
    pass
  
  server.server_close()
  print('dead')