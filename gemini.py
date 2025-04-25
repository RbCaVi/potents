import socket, ssl, urllib.parse
import OpenSSL
from cryptography.hazmat.primitives.serialization import pkcs12, Encoding, PrivateFormat, NoEncryption
import colorama
import sys
import re

colorama.init()

def myreceive(sock):
  data = b''
  while True:
    chunk = sock.recv(2048)
    if chunk == b'':
      break
    data += chunk
    #print(data)
  return data

# $mypwd = ConvertTo-SecureString -String 'passypass' -Force -AsPlainText
# $certname = "Robert Vail"    ## Replace {certificateName}
# $cert = New-SelfSignedCertificate -Subject "CN=$certname" -CertStoreLocation "Cert:\CurrentUser\My" -KeyExportPolicy Exportable -KeySpec Signature -KeyLength 2048 -KeyAlgorithm RSA -HashAlgorithm SHA256
# Export-PfxCertificate -Cert $cert -FilePath "C:\Users\Mr.tech\Desktop\$certname.pfx" -Password $mypwd   ## Specify your preferred location

with open('C:\\Users\\Mr.tech\\Desktop\\Robert Vail.pfx', 'rb') as f:
  pfx = pkcs12.load_pkcs12(f.read(), b'passypass')

with open("C:\\Users\\Mr.tech\\Desktop\\Robert Vail.pem", 'wb') as f2:
  f2.write(pfx.key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()))
  f2.write(pfx.cert.certificate.public_bytes(Encoding.PEM))
  if pfx.additional_certs:
    for _cert in pfx.additional_certs:
      f2.write(_cert.certificate.public_bytes(Encoding.PEM))

# $certname = "Robert Vail"    ## Replace {certificateName}
# $cert = New-SelfSignedCertificate -Subject "CN=$certname" -CertStoreLocation "Cert:\CurrentUser\My" -KeyExportPolicy Exportable -KeySpec Signature -KeyLength 2048 -KeyAlgorithm RSA -HashAlgorithm SHA256
# Export-Certificate -Cert $cert -FilePath "C:\Users\Mr.tech\Desktop\$certname.pfx"   ## Specify your preferred location

#with open("C:\\Users\\Mr.tech\\Desktop\\Robert Vail.cer", 'rb') as f:
  #with open("C:\\Users\\Mr.tech\\Desktop\\Robert Vail.pem", 'w') as f2:
    #f2.write(ssl.DER_cert_to_PEM_cert(f.read()))

def getcontext():
  context = ssl.create_default_context()
  context.check_hostname = False
  context.verify_mode = ssl.VerifyMode.CERT_NONE
  context.load_cert_chain("C:\\Users\\Mr.tech\\Desktop\\Robert Vail.pem")
  return context

NEEDINPUT = 10
NEEDSENSITIVEINPUT = 11
INPUTCODES = [NEEDINPUT, NEEDSENSITIVEINPUT]

SUCCESS = 20

TEMPREDIRECT = 30
PERMREDIRECT = 31
REDIRECTCODES = [PERMREDIRECT, TEMPREDIRECT]

TEMPFAIL = 40
UNAVAILABLE = 41
CGIFAIL = 42
PROXYFAIL = 43
RATELIMIT = 44
TEMPFAILCODES = [RATELIMIT, PROXYFAIL, UNAVAILABLE, CGIFAIL, TEMPFAIL]

PERMFAIL = 50
NOTFOUND = 51
GONE = 52
PROXYREFUSED = 53
BADREQUEST = 59
PERMFAILCODES = [BADREQUEST, PROXYREFUSED, GONE, NOTFOUND, PERMFAIL]

NEEDCERT = 60
UNAUTHORIZEDCERT = 61
INVALIDCERT = 62
AUTHCODES = [INVALIDCERT, UNAUTHORIZEDCERT, NEEDCERT]

def geminiget(url, server = None, port = None, context = getcontext()):
  if server is None:
    server = urllib.parse.urlparse(url).hostname
  if port is None:
    port = urllib.parse.urlparse(url).port
  if port is None:
    port = 1965
  conn = context.wrap_socket(socket.socket(socket.AF_INET))
  conn.connect((server, port))
  cert = conn.getpeercert()
  cert2 = ssl.get_server_certificate((server, port))
  conn.send(url.encode("utf-8") + b"\r\n")
  response = myreceive(conn)
  conn.close()
  response = parsegeminiresponse(response)
  response['cert'] = cert
  response['cert2'] = cert2
  return response

def parsegeminiresponse(response):
  # parser based on https://geminiprotocol.net/docs/protocol-specification.gmi
  # i'm not dealing with this VCHAR thing - i'm just decoding it by utf 8
  header,body = response.split(b'\r\n', 1) # i'm ignoring any provided body for the non 2x codes
  header = header.decode("utf-8")
  code = header[0], header[1]
  if code[1] not in '0123456789':
    raise ValueError("Invalid server response code: '{code[0]}{code[1]}'")
  if code[0] in '123':
    assert header[2] == ' '
    extradata = header[3:]
    if code[0] == '1':
      # unrecognized second digit is treated as 0
      if code[1] not in '01':
        code[1] = '0'
      return {"code": {'0': NEEDINPUT, '1': NEEDSENSITIVEINPUT}[code[1]], "prompt": extradata}
    if code[0] == '2':
      # there's only a 20 code
      return {"code": SUCCESS, "mimetype": extradata, "data": body.decode('utf-8')}
    if code[0] == '3':
      # unrecognized second digit is treated as 0
      if code[1] not in '01':
        code[1] = '0'
      return {"code": {'0': TEMPREDIRECT, '1': PERMREDIRECT}[code[1]], "redirect": extradata}
  elif code[0] in '456':
    if len(header) > 2:
      assert header[2] == ' '
      error = header[3:]
    else:
      error = None
    if code[0] == '4':
      # unrecognized second digit is treated as 0
      if code[1] not in '01234':
        code[1] = '0'
      return {"code": {'0': TEMPFAIL, '1': UNAVAILABLE, '2': RATELIMIT, '3': PROXYFAIL, '4': CGIFAIL}[code[1]], "error": error}
    if code[0] == '5':
      # unrecognized second digit is treated as 0
      if code[1] not in '01239':
        code[1] = '0'
      return {"code": {'0': NOTFOUND, '1': PERMFAIL, '2': GONE, '3': PROXYREFUSED, '9': BADREQUEST}[code[1]], "error": error}
    if code[0] == '6':
      # unrecognized second digit is treated as 0
      if code[1] not in '012':
        code[1] = '0'
      return {"code": {'0': NEEDCERT, '1': UNAUTHORIZEDCERT, '2': INVALIDCERT}[code[1]], "error": error}
  else:
    raise ValueError("Invalid server response code: '{code[0]}{code[1]}'")
  raise ValueError("no return?")

url = sys.argv[1]

def urljoin(base, url):
  # python urllib doesn't like the gemini scheme
  return urllib.parse.urlparse(urllib.parse.urljoin(urllib.parse.urlparse(base)._replace(scheme = "http").geturl(), url))._replace(scheme = "gemini").geturl()

history = []
request = True
while True:
  if request:
    try:
      print("\n\n\n")
      while True:
        resp = geminiget(url)
        code = resp['code']
        print("response with code", code)
        if code in INPUTCODES:
          userinput = input(resp['prompt'])
          url = urllib.parse.urlparse(url)._replace(query = userinput).geturl()
        if code in REDIRECTCODES:
          print("redirecting", url, 'to', resp['redirect'])
          url = urljoin(url, resp['redirect'])
        if code == SUCCESS:
          break
        if code in TEMPFAILCODES or code in PERMFAILCODES or code in AUTHCODES:
          break

      if resp['code'] == SUCCESS:
        mimetype = resp['mimetype']
        body = resp['data']
        if mimetype.startswith("text/gemini"):
          body = body.replace('\r\n', '\n')
          linknum = 1
          for line in body.split('\n'):
            if line.startswith('=>'):
              linkurl,label = re.match("=>\\s*(\\S+)(?:\\s+(.+))?", line).groups()
              print("=>", linknum, linkurl, label)
              linknum += 1
            else:
              print(line)
        print("mime type", mimetype)
      else:
        print(resp)
      print("fetched from", url)
    except KeyboardInterrupt:
      print("interrupted.")
    request = False

  command = input("> ")
  if len(command.split()) == 0:
    continue
  command,*args = command.split()
  print(command, args)
  if command == 'link':
    links = [re.match("=>\\s*(\\S+)(?:\\s+(.+))?", line).groups() for line in body.split("\n") if line.startswith('=>')]
    if len(links) == 0:
      print("no links on this page. try the `back` command")
    num = None
    if len(args) > 0:
      try:
        num = int(args[0]) - 1
        if num >= len(links) or num < 0:
          print("out of range:", num)
          num = None
      except:
        print("invalid number:", args[0])
    else:
      numlen = len(str(len(links)))
      namelen = max(len(text or "") for link,text in links)
      try:
        while True:
          for i,(link,text) in enumerate(links):
            print(str(i + 1).ljust(numlen), (text or "").ljust(namelen), link)
          inp = input()
          try:
            num = int(inp) - 1
            break
          except:
            print("invalid number:", inp)
          if num >= len(links) or num < 0:
            print("out of range:", num)
            num = None
      except KeyboardInterrupt:
        print("interrupted")
    if num is not None:
      link = links[num][0]
      print(url, "linked to", urljoin(url, link))
      history.append(url)
      url = urljoin(url, link)
      request = True
  elif command == 'visit' or command == 'cd':
    if len(args) > 0:
      link = args[0]
    else:
      link = input()
    history.append(url)
    url = urljoin(url, link)
    request = True
  elif command == 'view':
    print(body)
  elif command == 'back':
    if len(history) > 0:
      url = history.pop()
      request = True
    else:
      print("no history...")
  elif command == 'history':
    print(history)
  elif command == 'exit':
    break
  elif command == 'reload':
    request = True
  else:
    print("invalid command!!!!")