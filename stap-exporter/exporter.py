#!/usr/bin/python3

import os
import sys
import configparser
import subprocess
import shlex
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse
from time import time

script_dir = os.path.abspath(__file__ + "/../") + "/scripts/"
proc_path = "/proc/systemtap/__systemtap_exporter"


class Session:

    def __init__(self, name, sess_id):
        self.name = name
        self.id = sess_id
        self.cmd = self.get_cmd(name)
        self.timeout = None
        self.process = None
        self.start_time = None

    def begin(self):
        self.process = subprocess.Popen(shlex.split(self.cmd))

    def get_proc_path(self):
        return proc_path + str(self.id) + "/" + self.name

    def get_cmd(self, script):
        return "stap -m __systemtap_exporter%d %s%s" % (self.id,
                                                        script_dir,
                                                        script)


class SessionMgr:

    def __init__(self):
        self.counter = 0
        self.sessions = {}
        self.parse_conf()

    def create_sess(self, script_name):
        sess = Session(script_name, self.get_new_id())
        self.sessions[script_name] = sess
        return sess

    def start_sess(self, sess):
        """ Begin execution of script and record start time """
        sess.begin()
        sess.start_time = time()
        print("Launched " + sess.name)

    def start_sess_from_name(self, script_name):
        sess = self.sessions[script_name]
        self.start_sess(sess)

    def parse_conf(self):
        print("Reading config file")
        config = configparser.ConfigParser()

        try:
            config.read_file(open(script_dir + '/../exporter.conf'))
        except Exception as e:
            print("Unable to read exporter.conf: " + str(e))
            sys.exit(-1)

        self.port = int(config['DEFAULT']['port'])
        for sec in config.sections():
            sess = self.create_sess(sec)

            if 'timeout' in config[sec]:
                try:
                    sess.timeout = int(config[sec]['timeout'])
                except:
                    print("Unable to parse option 'timeout' of section " + sec)
                    sys.exit(-1)

            if 'startup' in config[sec] and config[sec]['startup'] == 'True':
                self.start_sess(sess)

    def sess_exists(self, name):
        return name in self.sessions

    def sess_started(self, name):
        return self.sessions[name].process is not None

    def get_new_id(self):
        ret = self.counter
        self.counter += 1
        return ret

    def terminate_sess(self, name, sess):
        print("Terminating " + name)
        sess.process.terminate()
        sess.process = None
        sess.start_time = None

    def check_timeouts(self):
        for (name, sess) in self.sessions.items():
            if (sess.start_time is not None
                    and sess.timeout is not None
                    and time() - sess.start_time >= sess.timeout):
                self.terminate_sess(name, sess)


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

    def send_msg(self, code, msg):
        self.set_headers(code, 'text/plain')
        self.wfile.write(bytes(msg, 'utf-8'))

    def do_GET(self):
        # remove the preceeding '/' from url
        name = urlparse(self.path).path[1:]
        mgr = self.sessmgr
        if not mgr.sess_exists(name):
            # exporter doesn't recognize the url
            self.send_msg(404, "File not found")
        elif mgr.sess_started(name):
            # session is already running, send metrics
            self.send_metrics(mgr.sessions[name])
        else:
            # launch session
            mgr.start_sess_from_name(name)
            self.send_msg(301, "Script launched, refresh page to access metrics.")

if __name__ == "__main__":
    sessmgr = HTTPHandler.sessmgr
    server_address = ('', sessmgr.port)
    httpd = HTTPServer(server_address, HTTPHandler)
    httpd.timeout = 5
    print("Exporter initialization complete")

    while 1:
        httpd.handle_request()
        sessmgr.check_timeouts()
