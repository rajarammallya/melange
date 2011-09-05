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

import gettext
import os

gettext.install('melange', unicode=1)


def melange_root_path():
    return os.path.dirname(__file__)


def melange_bin_path(filename="."):
    return os.path.join(melange_root_path(), "..", "bin", filename)


def melange_etc_path(filename="."):
    return os.path.join(melange_root_path(), "..", "etc", "melange", filename)
