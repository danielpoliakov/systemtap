#!/usr/bin/python3

from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse
from time import sleep, time
from pathlib import Path
import os
import subprocess
import shlex

script_dir = '/home/amerey/stap/systemtap/stap-exporter'
stap_path = '/home/amerey/stap/install/bin/stap'

proc_path = "/proc/systemtap/__systemtap_exporter"
scripts = ['/example1.stp']
run_at_startup = []

class Session:
    def __init__(self, path, sess_id, timeout=None):
        self.path = path
        self.id = sess_id
        self.cmd = self.get_cmd(path)
        self.timeout = timeout
        self.process = subprocess.Popen(shlex.split(self.cmd))

    def get_proc_path(self):
        return proc_path + str(self.id) + self.path

    def get_cmd(self, script):
        return "%s -m __systemtap_exporter%d %s%s" % (stap_path, self.id,
                                                      script_dir, script)

class SessionMgr:
    def __init__(self, scripts, startup_cmds):
      self.scripts = scripts
      self.counter = 0
      self.sessions = {}

      for script in run_at_startup:
          self.start_sess(script)

    # return 0 if init successful, else 1
    def start_sess(self, script_name): 
      sess = Session(script_name, self.counter)
      self.sessions[script_name] = sess
      self.counter += 1
      
      if self.wait_for_sess_init(sess) != 0:
          # init failed
          del self.sessions[script_name]
          sess.process.terminate()
          return 1
      return 0

    def is_started(path):
      return path in self.sessions

    def open_metrics(path):
      return open(module_path + path)

    # return 0 if init ok within 30 seconds, else 1.
    # Init is considered ok when the session's procfs probe file exists
    def wait_for_sess_init(self, sess):
      max_wait = 30
      pause_duration = 3
      path = Path(sess.get_proc_path())
      t0 = time()

      while time() - t0 < max_wait: 
          if path.exists():
              return 0
          sleep(pause_duration)
      return 1


class HTTPHandler(BaseHTTPRequestHandler):
    sessmgr = SessionMgr(scripts, run_at_startup)

    def set_headers(self, code, content_type, transfer_encoding=None):
        self.send_response(code)
        self.send_header('Content-type', content_type)

        if transfer_encoding:
            self.send_header('Transfer-Encoding', transfer_encoding)

        self.end_headers()

    def send_metrics(self, sess):
        metrics_path = sess.get_proc_path()
        self.set_headers(200, 'text/plain', 'chunked')
        try:
            with open(metrics_path) as metrics:
                for line in metrics:
                    self.wfile.write(b'%lx\r\n%b\r\n' % (len(line), bytes(line, 'utf-8')))
        except Exception as e:
            msg = bytes(str(e), 'utf-8')
            self.wfile.write(b'%lx\r\n%b\r\n' % (len(msg), msg))

        self.wfile.write(b'0\r\n\r\n')

    def send_msg(self, code, msg):
        self.set_headers(code, 'text/html')
        self.wfile.write(b'<html><body><h3>%b</h3></body></html>' % bytes(msg, 'utf-8'))

    def do_GET(self):
        url = urlparse(self.path)

        if url.path in self.sessmgr.sessions:
            # send metrics from already started session
            sess = self.sessmgr.sessions[url.path]
            self.send_metrics(sess)
        elif url.path in self.sessmgr.scripts:
            if self.sessmgr.start_sess(url.path) != 0:
               self.send_msg(500, "Unable to start stap session")
            else:
               self.send_msg(200, "Script successfully started. \
                                   Refresh page to access metrics.")
        else:
            self.send_msg(404, "Error 404: file not found") 


if __name__ == "__main__":
    server_address = ('', 9900)
    httpd = HTTPServer(server_address, HTTPHandler)
    httpd.serve_forever()
