2# vim: tabstop=4 shiftwidth=4 softtabstop=4

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
from webob.exc import HTTPUnprocessableEntity

from melange.common import wsgi
from melange.ipam import models
from melange.ipam.models import IpBlock
from melange.ipam.models import IpAddress
from melange.db import session

class IpBlockController(wsgi.Controller):
    def index(self, request):
        return "index"

    def create(self,request):
        block = IpBlock.create(request.params)
        return self._ip_block_dict(block)

    def show(self, request,id):
        return self._ip_block_dict(IpBlock.find(id))
        
    def version(self,request):
        return "Melange version 0.1"

    def _ip_block_dict(self,ip_block):
        return Response(body=json.dumps({'id':ip_block.id,
                                         'network_id':ip_block.network_id,
                                         'cidr':ip_block.cidr}),
                        content_type = "application/json")

class IpAddressController(wsgi.Controller):
    def index(self, request, ip_block_id):
        addresses = IpAddress.find_all_by_ip_block(ip_block_id)
        return self._json_response(dict(ip_addresses=[self._ip_address_dict(ip_address)
                                  for ip_address in addresses]))
    
    def show(self, request,id, ip_block_id):
        return self._ip_address_dict_response(IpAddress.find(id))

    def create(self, request, ip_block_id):
        try:
            ip_block = IpBlock.find(ip_block_id)
            ip_address = ip_block.allocate_ip(request.params.get('port_id',None))
            return self._ip_address_dict_response(ip_address)
        except models.NoMoreAddressesException:
            raise HTTPUnprocessableEntity("ip block is full",
                                          request=request, content_type="text\plain")

    def _ip_address_dict_response(self, ip_address):
        return self._json_response(self._ip_address_dict(ip_address))

    def _json_response(self, body):
        return Response(body=json.dumps(body), content_type="application/json")

    def _ip_address_dict(self,ip_address):
        return {'id':ip_address.id,
                'ip_block_id':ip_address.ip_block_id,
                'address':ip_address.address,
                'port_id':ip_address.port_id}
    
class API(wsgi.Router):                                                                
    def __init__(self, options):                                                       
        self.options = options
        mapper = routes.Mapper()                                                       
        ip_block_controller = IpBlockController()
        ip_address_controller = IpAddressController()
        mapper.resource("ip_block", "/ipam/ip_blocks", controller=ip_block_controller)
        mapper.resource("ip_address", "ip_addresses", controller=ip_address_controller,
                        parent_resource=dict(member_name="ip_block",
                                             collection_name="/ipam/ip_blocks"))
        mapper.connect("/", controller=ip_block_controller, action="version")
        super(API, self).__init__(mapper)
                                                                                      
def app_factory(global_conf, **local_conf):                                            
    conf = global_conf.copy()                                                          
    conf.update(local_conf)
    return API(conf)
