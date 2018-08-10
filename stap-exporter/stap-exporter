#!/usr/bin/python3

import os
import sys
import argparse
import subprocess
import shlex
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse
from time import time

script_dir = (os.path.abspath(__file__ + "/../../") 
              + "/testsuite/systemtap.examples/stap-exporter-scripts/")
proc_path = "/proc/systemtap/__systemtap_exporter"


class Session:

    def __init__(self, name, sess_id):
        self.name = name
        self.id = sess_id
        self.cmd = self.get_cmd(name)
        self.process = None
        self.start_time = None

    def begin(self):
        self.process = subprocess.Popen(shlex.split(self.cmd))

    def get_proc_path(self):
        return proc_path + str(self.id) + "/" + self.name

    def set_start_time(self):
        self.start_time = time()

    def get_cmd(self, script):
        return "stap -m __systemtap_exporter%d --example %s" % (self.id,
                                                                script)


class SessionMgr:

    def __init__(self):
        self.counter = 0
        self.port = None
        self.timeout = None
        self.sessions = {}
        self.parse_cmdline()
        self.run_autostart_scripts()

    def start_sess(self, script_name):
        """ Begin execution of script and record start time """
        s = Session(script_name, self.get_new_id())
        self.sessions[script_name] = s
        s.begin()
        s.set_start_time()

    def parse_cmdline(self):
         p = argparse.ArgumentParser(description='Systemtap-prometheus interoperation mechanism')
         p.add_argument('-p', '--port', nargs=1, default=[9900], type=int)
         p.add_argument('-t', '--timeout', nargs=1, default=[None], type=int)
          
         opts = p.parse_args()
         self.port = opts.port[0]
         self.timeout = opts.timeout[0]

    def run_autostart_scripts(self):
        scripts = os.listdir(script_dir + "autostart/")
        for name in scripts:
            self.start_sess(name)

    def sess_started(self, name):
         return name in self.sessions 

    def get_new_id(self):
        ret = self.counter
        self.counter += 1
        return ret

    def check_timeouts(self):
        term = []
        for (name, sess) in self.sessions.items():
            if ((sess.start_time is not None
                    and self.timeout is not None
                    and time() - sess.start_time >= self.timeout)
                    or sess.process.poll() is not None):
                print("Terminating " + name)
                sess.process.terminate()
                term.append(name)
        for name in term:
                self.sessions[name].process.wait(1)
                self.sessions.pop(name, None)


class HTTPHandler(BaseHTTPRequestHandler):
    sessmgr = SessionMgr()

    def set_headers(self, code, content_type):
        self.send_response(code)
        self.send_header('Content-type', content_type)
        self.end_headers()

    def send_metrics(self, sess):
        metrics_path = sess.get_proc_path()
        try:
            with open(metrics_path) as metrics:
                self.set_headers(200, 'text/plain')
                self.wfile.write(bytes(metrics.read(), 'utf-8'))
        except:
            self.set_headers(501, 'text/plain')
            self.wfile.write(bytes('Metrics currently unavailable', 'utf-8'))
        sess.set_start_time()

    def send_msg(self, code, msg):
        self.set_headers(code, 'text/plain')
        self.wfile.write(bytes(msg, 'utf-8'))

    def do_GET(self):
        # remove the preceeding '/' from url
        name = urlparse(self.path).path[1:]
        mgr = self.sessmgr
        if mgr.sess_started(name):
            # session is already running, send metrics
            self.send_metrics(mgr.sessions[name])
        else:
            # launch session
            mgr.start_sess(name)
            self.send_msg(301, "Refresh page to access metrics.")

if __name__ == "__main__":
    sessmgr = HTTPHandler.sessmgr
    server_address = ('', sessmgr.port)
    httpd = HTTPServer(server_address, HTTPHandler)
    httpd.timeout = 5
    print("Exporter initialization complete")

    while 1:
        httpd.handle_request()
        sessmgr.check_timeouts()
