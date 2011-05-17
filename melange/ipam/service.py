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

class BaseController(wsgi.Controller):
    def _json_response(self, body):
        return Response(body=json.dumps(body), content_type="application/json")


class IpBlockController(BaseController):
    def index(self, request):
        return "index"

    def create(self,request):
        try:
            block = IpBlock.create(request.params)
            return self._json_response(block.data())
        except models.InvalidModelError, e:
            raise HTTPBadRequest("block parameters are invalid : %s" % e,
                                 request=request,
                                 content_type="text\plain")

    def show(self, request,id):
        return self._json_response(IpBlock.find(id).data())
        
    def version(self,request):
        return "Melange version 0.1"

class IpAddressController(BaseController):
    def index(self, request, ip_block_id):
        addresses = IpAddress.find_all_by_ip_block(ip_block_id)
        return self._json_response(dict(ip_addresses=[ip_address.data()
                                   for ip_address in addresses]))
    
    def show(self, request,address,ip_block_id):
        return self._json_response(IpBlock.find(ip_block_id).\
                                   find_allocated_ip(address).data())

    def delete(self, request,address,ip_block_id):
        IpBlock.find(ip_block_id).deallocate_ip(address)

    def create(self, request, ip_block_id):
        try:
            ip_block = IpBlock.find(ip_block_id)
            ip_address = ip_block.allocate_ip(request.params.get('port_id',None))
            return self._json_response(ip_address.data())
        except models.NoMoreAdressesError:
            raise HTTPUnprocessableEntity("ip block is full",
                                          request=request, content_type="text\plain")

class NatController(BaseController):

    def create_locals(self,request,ip_block_id,address):
        global_ip = IpBlock.find_or_allocate_ip(ip_block_id,address)
        local_ips = self._parse_ips(request.params["ip_addresses"])
        global_ip.add_inside_locals(local_ips)
        
    def create_globals(self,request,ip_block_id,address):
        local_ip = IpBlock.find_or_allocate_ip(ip_block_id,address)
        global_ips = self._parse_ips(request.params["ip_addresses"])
        local_ip.add_inside_globals(global_ips)

    def show_globals(self, request, ip_block_id, address):
        ip = IpAddress.find_by_block_and_address(ip_block_id, address)
        return self._get_addresses(ip.inside_globals())

    def show_locals(self, request, ip_block_id, address):
        ip = IpAddress.find_by_block_and_address(ip_block_id, address)
        return self._get_addresses(ip.inside_locals())

    def _get_addresses(self,ips):
        return self._json_response(
            dict(ip_addresses=[ip_address.data() for ip_address in ips]))    
    
    def _parse_ips(self, addresses):
        return [IpBlock.find_or_allocate_ip(address["ip_block_id"],
                                                 address["ip_address"])
                     for address in json.loads(addresses)]

class API(wsgi.Router):                                                                
    def __init__(self, options):                                                       
        self.options = options
        mapper = routes.Mapper()                                                       
        ip_block_controller = IpBlockController()
        ip_address_controller = IpAddressController()
        nat_controller = NatController()
        mapper.resource("ip_block", "/ipam/ip_blocks", controller=ip_block_controller)

        with mapper.submapper(controller=nat_controller,
                              path_prefix="/ipam/ip_blocks/{ip_block_id}/"
                                          "ip_addresses/{address:.+?}/") as submap:
                  submap.connect("inside_locals", action="create_locals",
                                 conditions=dict(method=["POST"]))
                  submap.connect("inside_globals", action="create_globals",
                                 conditions=dict(method=["POST"]))                  
                  submap.connect("inside_globals", action="show_globals",
                       conditions=dict(method=["GET"]))
                  submap.connect("inside_locals", action="show_locals",
                       conditions=dict(method=["GET"]))

        mapper.connect("/ipam/ip_blocks/{ip_block_id}/ip_addresses/{address:.+}",
                       controller=ip_address_controller, action = "show",
                       conditions=dict(method=["GET"]))
        mapper.connect("/ipam/ip_blocks/{ip_block_id}/ip_addresses/{address:.+}",
                       controller=ip_address_controller, action = "delete",
                       conditions=dict(method=["DELETE"]))
        mapper.resource("ip_address", "ip_addresses", controller=ip_address_controller,
                         parent_resource=dict(member_name="ip_block",
                                              collection_name="/ipam/ip_blocks"))
        mapper.connect("/", controller=ip_block_controller, action="version")
        super(API, self).__init__(mapper)
                                                                                      
def app_factory(global_conf, **local_conf):                                            
    conf = global_conf.copy()                                                          
    conf.update(local_conf)
    return API(conf)
