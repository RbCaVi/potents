import http.server
import multipart
import os

hostname = '0.0.0.0'
port = 9999

content = b'''
<!doctype html>
<html>
  <head></head>
  <body>
    <form method = 'POST' enctype = 'multipart/form-data'>
      <input type = 'file' name = 'file' multiple>
      <input type = 'submit'>
    </form>
  </body>
</html>
'''

class FileUploader(http.server.BaseHTTPRequestHandler):
  def do_GET(self):
    self.send_response(200)
    self.end_headers()
    self.wfile.write(content)
  
  def do_POST(self):
    env = {
      'wsgi.input': self.rfile,
      'CONTENT_TYPE': self.headers['content-type'],
      'CONTENT_LENGTH': self.headers['content-length'],
    }
    forms,files = multipart.parse_form_data(env)
    print(forms, files)
    for part in files.getall('file'):
      data = part.file.read()
      with open(os.path.basename(part.filename), 'wb') as f:
        f.write(data)
    self.do_GET()

if __name__ == '__main__':
  server = http.server.ThreadingHTTPServer((hostname, port), FileUploader)
  print(f'server at http://{hostname}:{port}')
  
  try:
    server.serve_forever()
  except KeyboardInterrupt:
    pass
  
  server.server_close()
  print('dead')