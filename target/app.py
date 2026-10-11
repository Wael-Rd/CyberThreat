"""Toy vulnerable service: synthetic accounts, no shell or external data."""
import json, re, sqlite3, threading, time
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs
DB = sqlite3.connect(':memory:', check_same_thread=False)
DB.executescript("CREATE TABLE users(username TEXT,password TEXT); INSERT INTO users VALUES('labuser','LabOnly-2026'),('analyst','SyntheticOnly');")
LOCK = threading.Lock()
MODE = 'vulnerable'
FAILURES = {}
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def reply(self, code, obj, event):
        raw = json.dumps(obj).encode()
        self.send_response(code); self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(raw))); self.end_headers(); self.wfile.write(raw)
        run = self.headers.get('X-Lab-Run','manual')
        if not re.fullmatch(r'[a-zA-Z0-9_-]{1,64}',run): run='manual'
        directory = Path('/evidence') / run
        directory.mkdir(exist_ok=True)
        record = dict(time=time.time(),source=self.client_address[0],method=self.command,path=self.path,status=code,event=event,mode=MODE)
        with LOCK:
            with (directory/'app.jsonl').open('a') as f: f.write(json.dumps(record)+'\n')
    def do_GET(self):
        url=urlsplit(self.path)
        if url.path=='/health': return self.reply(200,{'ok':True,'mode':MODE},'health')
        if url.path=='/': return self.reply(200,{'project':'laboratoire cybermenaces'},'baseline')
        if url.path=='/users':
            query=parse_qs(url.query).get('name',['labuser'])[0][:200]
            with LOCK:
                if MODE=='hardened': rows=DB.execute('SELECT username FROM users WHERE username=?',(query,)).fetchall()
                else:
                    try: rows=DB.execute("SELECT username FROM users WHERE username='"+query+"'").fetchall()
                    except sqlite3.Error: rows=[]
            return self.reply(200,{'users':[r[0] for r in rows]},'user_lookup')
        self.reply(404,{'error':'missing'},'not_found')
    def do_POST(self):
        global MODE
        length=int(self.headers.get('Content-Length','0'))
        if length>2048: return self.reply(413,{'error':'too_large'},'rejected')
        try: data=json.loads(self.rfile.read(length))
        except (ValueError,TypeError): return self.reply(400,{'error':'json'},'rejected')
        if self.path=='/control':
            if data.get('mode') not in ('vulnerable','hardened'): return self.reply(400,{},'control')
            MODE=data['mode']; FAILURES.clear()
            return self.reply(200,{'mode':MODE},'control')
        if self.path!='/login': return self.reply(404,{},'not_found')
        source=self.client_address[0]; now=time.monotonic()
        recent=[t for t in FAILURES.get(source,[]) if now-t<60]
        if MODE=='hardened' and len(recent)>=3: return self.reply(429,{'error':'rate_limited'},'login_blocked')
        with LOCK: ok=DB.execute('SELECT username FROM users WHERE username=? AND password=?',(str(data.get('username','')),str(data.get('password','')))).fetchone() is not None
        if not ok: FAILURES[source]=recent+[now]
        self.reply(200 if ok else 401,{'authenticated':ok},'login_success' if ok else 'login_failure')
ThreadingHTTPServer(('0.0.0.0',8080),Handler).serve_forever()
