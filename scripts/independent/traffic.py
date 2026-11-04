"""New bounded socket/http generator, separate from the training agent."""
import sys,json,socket,time,random,threading,http.server,base64,os
ALLOWED={f'192.168.56.{i}' for i in range(11,15)}
mode=sys.argv[1]
if mode=='server':
 host=sys.argv[2];assert host in ALLOWED
 def udp(port,echo):
  s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind((host,port))
  while True:
   data,addr=s.recvfrom(2048)
   if echo and addr[0] in ALLOWED:s.sendto(data,addr)
 class Handler(http.server.BaseHTTPRequestHandler):
  def do_GET(self):
   if self.client_address[0] not in ALLOWED:self.send_error(403);return
   valid=self.headers.get('Authorization')=='Basic '+base64.b64encode(b'demo:correct').decode()
   self.send_response(200 if valid else 401);body=b'new service response '+b'x'*256;self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
  def log_message(self,*a):pass
 for port,echo in [(8083,True),(8084,False)]:threading.Thread(target=udp,args=(port,echo),daemon=True).start()
 threading.Timer(900,lambda:os._exit(0)).start()
 http.server.ThreadingHTTPServer((host,8082),Handler).serve_forever()
else:
 cfg=json.loads(sys.argv[2]);src,target=cfg['src'],cfg['dst'];assert src in ALLOWED and target in ALLOWED and src!=target
 rng=random.Random(cfg['seed']);end=time.monotonic()+min(12,cfg['duration']);events=[];i=0
 def bind(s):s.bind((src,0));events.append(s.getsockname()[1])
 while time.monotonic()<end and i<1500:
  i+=1;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM if cfg['kind']=='udp' else socket.SOCK_STREAM);bind(s);s.settimeout(.12)
  try:
   if cfg['kind']=='udp':
    for _ in range(rng.randint(1,12)):s.sendto(rng.randbytes(rng.choice([32,99,333,777,1200])),(target,cfg['port']))
    if cfg['port']==8083:s.recvfrom(2048)
   elif cfg['kind']=='scan':s.connect_ex((target,rng.randrange(8200,8264)))
   else:
    s.connect((target,8082));password='correct' if cfg['label']=='BENIGN' and rng.random()<.65 else 'wrong'+str(rng.randrange(9999));auth=base64.b64encode(('demo:'+password).encode()).decode();s.sendall(('GET /new-login HTTP/1.0\r\nHost: lab\r\nAuthorization: Basic '+auth+'\r\n\r\n').encode())
    while s.recv(4096):pass
  except OSError:pass
  finally:s.close()
  time.sleep(rng.expovariate(cfg['rate']))
 print(json.dumps({'src':src,'dst':target,'ports':events,'label':cfg['label'],'connections':i}))
