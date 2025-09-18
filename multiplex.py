# https://pythonbasics.org/webserver/
import http.server
import requests
import urllib.parse
import multipart
import re
import json

hostname = "localhost"
serverPort = 8001

with open('multiplexed-pages.json') as f:
    mapping = json.load(f)

class MyHandler(http.server.BaseHTTPRequestHandler):
    def send(self, method, base, path, basepath):
        env = {'wsgi.input': self.rfile, 'CONTENT_TYPE': self.headers['content-type'], 'CONTENT_LENGTH': self.headers['content-length']}
        forms,files = multipart.parse_form_data(env)
        #print(len(forms), len(files))
        #print(forms, {k:v for k,v in forms.items()}, files)
        fullpath = urllib.parse.urljoin(base + '/', path)
        #print(method, fullpath, {k:v for k,v in self.headers.items() if not v.startswith('multipart/form-data')}, {k:v for k,v in forms.items()})
        headers = {k:v for k,v in self.headers.items() if not v.startswith('multipart/form-data')}
        headers['Host'] = base.split('://')[1].split('/')[0].split(':')[0]
        resp = requests.request(
            method,
            fullpath,
            headers = headers,
            data = {k:v for k,v in forms.items()},
            files = {(k, f.file) for k in files for f in files.getall(k)},
        )
        #print(resp.content)
        #print(resp.headers)
        base = base.split('://', 1)[1]
        content = resp.content.replace(
            bytes(f'{hostname}:{serverPort}/', 'utf-8'),
            bytes(f'{hostname}:{serverPort}{basepath}', 'utf-8')
        ).replace(
            bytes(f'{hostname}:{serverPort}', 'utf-8'),
            bytes(f'{hostname}:{serverPort}{basepath}', 'utf-8')
        ).replace(
            bytes(f'{hostname}:{serverPort}{basepath}{basepath}', 'utf-8'),
            bytes(f'{hostname}:{serverPort}{basepath}', 'utf-8')
        ).replace(
            bytes(base + '/', 'utf-8'),
            bytes(f'{hostname}:{serverPort}{basepath}', 'utf-8')
        ).replace(
            bytes(base, 'utf-8'),
            bytes(f'{hostname}:{serverPort}{basepath}', 'utf-8')
        )
        #if 'html' not in resp.headers['content-type']:
        #    print(content)
        if b'<base' not in content and 'html' in resp.headers.get('content-type', ''):
            content = re.sub(b'((href|src)\\s*=\\s*(\'|"))/', b'\\1' + bytes(basepath, 'utf-8'), content)
            def replacement(m):
                if m[4] == b'data:':
                    return m[0]
                return m[1] + bytes(basepath, 'utf-8') + m[4]
            content = re.sub(b'((href|src)\\s*=\\s*(\'|"))([^/]....)', replacement, content)
        self.send_response(resp.status_code)
        for header,value in resp.headers.items():
            if header.lower() == 'content-encoding':
                continue
            if header.lower() == 'content-length':
                value = str(len(content))
            self.send_header(header, value)
        self.end_headers()
        self.wfile.write(content)

    def do(self, method):
        print(method, self.path)
        for basepath,base in mapping.items():
            if self.path.startswith(basepath):
                path = self.path[len(basepath):]
                self.send(method, base, path, basepath)
                return
        self.send_response(404)
        self.end_headers()

    def do_GET(self):
        self.do('GET')

    def do_POST(self):
        self.do('POST')

if __name__ == "__main__":
    webServer = http.server.ThreadingHTTPServer((hostname, serverPort), MyHandler)
    print("Server started at http://%s:%s" % (hostname, serverPort))

    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
    print("Server stopped.")
