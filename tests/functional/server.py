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
import time
import datetime
import urllib2


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

    def start(self):
        pid = os.fork()
        if pid == 0:
            os.setsid()
            self.close_stdio()
            try:
                os.system("(%s -p %s >func_test.log)" % (self.name, self.port))
            except OSError:
                os._exit(1)
            os._exit(0)
        else:
            self.wait_till_running()

    def stop(self):
        os.system("ps x -o pid,command | grep -v 'grep'|"
                  "grep 'bin/melange' | awk '{print $1}'| xargs kill -9")

    def wait_till_running(self, timeout=10):
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
