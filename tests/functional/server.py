# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2010 OpenStack, LLC
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

import os
import sys
import time
import datetime
import urllib2

from signal import SIGTERM


class Server(object):

    def __init__(self, name, port=9292):
        self.name = name
        self.port = port

    def restart(self):
        self.stop()
        self.start()

    def close_stdio(self):
        with open(os.devnull, 'r+b') as nullfile:
            for desc in (0, 1, 2):  # close stdio
                try:
                    os.dup2(nullfile.fileno(), desc)
                except OSError:
                    pass

    def pid_file_path(self):
        return os.path.join('/', 'tmp', self.name + ".pid")

    def write_pidfile(self):
        try:
            with open(self.pid_file_path(), 'w') as pidfile:
                pidfile.write(str(os.getpid()))
        except IOError, e:
            sys.exit(str(e))

    def start(self):
        pid = os.fork()
        if pid == 0:
            os.setsid()
            self.close_stdio()
            self.write_pidfile
            try:
                os.system("bin/{0}".format(self.name))
            except OSError, e:
                sys.exit(str(e))
            sys.exit(0)
        else:
            self.wait()

    def stop(self):
        try:
            with open(self.pid_file_path(), 'r') as pidfile:
                pid = int(pidfile.read())
                os.kill(pid, SIGTERM)
                os.remove(pidfile)
        except (OSError, IOError, ValueError), e:
            pass

    def wait(self, timeout=10):
        now = datetime.datetime.now()
        timeout_time = now + datetime.timedelta(seconds=timeout)
        while (timeout_time > now):
            if self.running():
                return
            now = datetime.datetime.now()
            time.sleep(0.05)
        print("Failed to start servers.")

    def running(self):
        try:
            urllib2.urlopen("http://localhost:{0}".format(self.port))
            return True
        except urllib2.URLError:
            return False
