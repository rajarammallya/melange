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
from webob.exc import HTTPUnprocessableEntity,HTTPBadRequest

from melange.common import wsgi
from melange.ipam import models
from melange.ipam.models import IpBlock
from melange.ipam.models import IpAddress
from melange.db import session

class IpBlockController(wsgi.Controller):
    def index(self, request):
        return "index"

    def create(self,request):
        try:
            block = IpBlock.create(request.params)
            return self._ip_block_dict(block)
        except models.InvalidModelError, e:
            raise HTTPBadRequest("block parameters are invalid : %s" % e,
                                 request=request,
                                 content_type="text\plain")

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
    
    def show(self, request,address,ip_block_id):
        return self._ip_address_dict_response(IpBlock.find(ip_block_id).\
                                              find_allocated_ip(address))

    def delete(self, request,address,ip_block_id):
        IpBlock.find(ip_block_id).deallocate_ip(address)

    def create(self, request, ip_block_id):
        try:
            ip_block = IpBlock.find(ip_block_id)
            ip_address = ip_block.allocate_ip(request.params.get('port_id',None))
            return self._ip_address_dict_response(ip_address)
        except models.NoMoreAdressesError:
            raise HTTPUnprocessableEntity("ip block is full",
                                          request=request, content_type="text\plain")

    def _ip_address_dict_response(self, ip_address):
        return self._json_response(self._ip_address_dict(ip_address))

    def _json_response(self, body):
        return Response(body=json.dumps(body), content_type="application/json")

    def _ip_address_dict(self,ip_address):
        return {'id':ip_address.id,
                'address':ip_address.address,
                'port_id':ip_address.port_id}

class NatController(wsgi.Controller):

    def create_locals(self,request,ip_block_id,address):
        ip = IpBlock.find(ip_block_id).find_or_allocate_ip_by_address(address)
        
        ips = []
        for ip_address in json.loads(request.params["ip_addresses"]):
            block = IpBlock.find(ip_address["ip_block_id"])
            ips.append(block.find_or_allocate_ip_by_address(ip_address["ip_address"]))
                       
        ip.add_inside_locals(ips)

class API(wsgi.Router):                                                                
    def __init__(self, options):                                                       
        self.options = options
        mapper = routes.Mapper()                                                       
        ip_block_controller = IpBlockController()
        ip_address_controller = IpAddressController()
        nat_controller = NatController()
        mapper.resource("ip_block", "/ipam/ip_blocks", controller=ip_block_controller)
        mapper.connect("/ipam/ip_blocks/{ip_block_id}/ip_addresses/{address:.+}",
                       controller=ip_address_controller, action = "show",
                       conditions=dict(method=["GET"]))
        mapper.connect("/ipam/ip_blocks/{ip_block_id}/ip_addresses/{address:.+}",
                       controller=ip_address_controller, action = "delete",
                       conditions=dict(method=["DELETE"]))
        mapper.resource("ip_address", "ip_addresses", controller=ip_address_controller,
                         parent_resource=dict(member_name="ip_block",
                                              collection_name="/ipam/ip_blocks"))
        mapper.connect("/ipam/ip_blocks/{ip_block_id}/ip_addresses/{address:.+?}/inside_locals",
                       controller=nat_controller, action="create_locals")
        
        mapper.connect("/", controller=ip_block_controller, action="version")
        super(API, self).__init__(mapper)
                                                                                      
def app_factory(global_conf, **local_conf):                                            
    conf = global_conf.copy()                                                          
    conf.update(local_conf)
    return API(conf)
