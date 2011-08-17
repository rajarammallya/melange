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
import os
import routes

from melange.common import wsgi


class VersionsController(wsgi.Controller):

    _serialization_metadata = {
            "application/xml": {
                "attributes": {
                    "version": ["status", "name"],
                    "link": ["rel", "href"],
                }
            }
        }

    def index(self, request):
        """Respond to a request for all OpenStack API versions."""
        versions = [Version("v0.1", "CURRENT", request.application_url).data()]
        return dict(versions=versions)


class Version(object):

    def __init__(self, name, status, base_url):
        self.name = name
        self.status = status
        self.base_url = base_url

    def data(self):
        return dict(name=self.name,
                    status=self.status,
                    links=[dict(rel="self",
                                href=self.url())])

    def url(self):
        return os.path.join(self.base_url, self.name)


class VersionsAPI(wsgi.Router):
    def __init__(self, options={}):
        self.options = options
        mapper = routes.Mapper()
        mapper.connect("/", controller=VersionsController(), action="index")
        super(VersionsAPI, self).__init__(mapper)


def app_factory(global_conf, **local_conf):
    conf = global_conf.copy()
    conf.update(local_conf)
    return VersionsAPI(conf)
