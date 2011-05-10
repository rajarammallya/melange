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

import json
import routes
from webob import Response

from melange.common import wsgi
from melange.ipam.models import IpBlock
from melange.db import session

class IpBlockController(wsgi.Controller):
    def index(self, request):
        return "index"

    def create(self,request):
        block = IpBlock()
        block.update(request.params)
        block.save()
        return Response(body=json.dumps({'id':block.id, 'network_id':block.network_id,
                'cidr':block.cidr}), content_type = "application/json")

    def version(self,request):
        return "Melange version 0.1"

class API(wsgi.Router):                                                                
    def __init__(self, options):                                                       
        self.options = options
        session.configure_db(options)
        mapper = routes.Mapper()                                                       
        controller = IpBlockController()                                            
        mapper.resource("ip_block", "/ipam/ip_blocks", controller=controller)
        mapper.connect("/", controller=controller, action="version")
        super(API, self).__init__(mapper)
                                                                                      
def app_factory(global_conf, **local_conf):                                            
    conf = global_conf.copy()                                                          
    conf.update(local_conf)
    return API(conf)
