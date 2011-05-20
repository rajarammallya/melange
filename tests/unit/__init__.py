# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2011 OpenStack LLC.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

# See http://code.google.com/p/python-nose/issues/detail?id=373
# The code below enables nosetests to work with i18n _() blocks
import __builtin__
import unittest
setattr(__builtin__, '_', lambda x: x)

from melange.db import session


class BaseTest(unittest.TestCase):

    def setUp(self):
        session.clean_db()
        self.test_setup()

    def test_setup(self):
        """ implement this in inheritors instead of using setup directly """
        pass


def setup():
    import os
    import urlparse
    from melange.common import config
    from melange.db import migration
    from melange.ipam import models
    conf_file, conf = config.load_paste_config("melange",
                        {"config_file":
                         os.path.abspath("../../etc/melange.conf.test")}, None)
    conn_string = conf["sql_connection"]
    conn_pieces = urlparse.urlparse(conn_string)
    testdb = conn_pieces.path.strip('/')
    if os.path.exists(testdb):
        os.unlink(testdb)

    migration.db_sync(conf)
    conf["models"] = models.models()
    session.configure_db(conf)
