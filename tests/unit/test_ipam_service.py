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
from webtest import TestApp

from tests.unit import BaseTest
from tests.unit import test_config_path
from melange.common import config
from melange.ipam import models
from melange.ipam.models import IpBlock, IpAddress, Policy, IpRange, IpOctet
from tests.unit.factories.models import (PublicIpBlockFactory,
                                         PrivateIpBlockFactory, PolicyFactory,
                                         IpRangeFactory, IpOctetFactory)


class BaseTestController(BaseTest):

    def setUp(self):
        super(BaseTestController, self).setUp()
        conf, melange_app = config.load_paste_app('melange',
                {"config_file": test_config_path()}, None)
        self.app = TestApp(melange_app)

    def assertErrorResponse(self, response, expected_status,
                            expected_error):
        self.assertEqual(response.status, expected_status)
        self.assertTrue(expected_error in response.body)


class IpBlockControllerBase():

    def test_create_with_bad_cidr(self):
        response = self.app.post("%s" % self.ip_block_path,
                                 {'network_id': "300", 'cidr': "10..."},
                                 status="*")

        self.assertEqual(response.status, "400 Bad Request")
        self.assertTrue('cidr is invalid' in response.body)

    def test_show(self):
        block = self._ip_block_factory()
        response = self.app.get("%s/%s" % (self.ip_block_path, block.id))

        self.assertEqual(response.status, "200 OK")
        self.assertEqual(response.json, dict(ip_block=block.data()))

    def test_delete(self):
        block = self._ip_block_factory()
        response = self.app.delete("%s/%s" % (self.ip_block_path, block.id))

        self.assertEqual(response.status, "200 OK")
        self.assertRaises(models.ModelNotFoundError, IpBlock.find, block.id)

    def test_index(self):
        blocks = [self._ip_block_factory(cidr="192.1.1.1/30"),
                  self._ip_block_factory(cidr="192.2.2.2/30"),
                  self._ip_block_factory(cidr="192.3.3.3/30")]
        response = self.app.get("%s" % self.ip_block_path)

        self.assertEqual(response.status, "200 OK")
        response_blocks = response.json['ip_blocks']
        self.assertEqual(len(response_blocks), 3)
        self.assertEqual(response_blocks, _data_of(*blocks))

    def test_index_with_pagination(self):
        blocks = [self._ip_block_factory(cidr="10.1.1.0/32"),
                  self._ip_block_factory(cidr='10.2.1.0/32'),
                  self._ip_block_factory(cidr='10.3.1.0/32'),
                  self._ip_block_factory(cidr='10.4.1.0/32')]

        response = self.app.get("%s?limit=2&marker=%s"
                                % (self.ip_block_path, blocks[1].id))

        response_blocks = response.json['ip_blocks']
        self.assertEqual(response.status, "200 OK")
        self.assertEqual(len(response_blocks), 2)
        self.assertEqual(response_blocks, _data_of(blocks[2], blocks[3]))


class TestPublicIpBlockController(IpBlockControllerBase, BaseTestController):

    def setUp(self):
        self.ip_block_path = "/ipam/public_ip_blocks"
        super(TestPublicIpBlockController, self).setUp()

    def _ip_block_factory(self, **kwargs):
        return PublicIpBlockFactory(**kwargs)

    def test_create(self):
        response = self.app.post("/ipam/public_ip_blocks.json",
                                 {'network_id': "300", 'cidr': "10.1.1.0/2"})

        self.assertEqual(response.status, "201 Created")
        saved_block = IpBlock.find_by_network_id("300")
        self.assertEqual(saved_block.cidr, "10.1.1.0/2")
        self.assertEqual(saved_block.type, "public")
        self.assertEqual(saved_block.tenant_id, None)
        self.assertEqual(response.json, dict(ip_block=saved_block.data()))

    def test_cannot_create_duplicate_public_cidr(self):
        self.app.post("/ipam/public_ip_blocks",
                      {"network_id": "12200", 'cidr': "192.1.1.1/2"})

        duplicate_block_response = self.app.post("/ipam/public_ip_blocks",
                      {"network_id": "22200", 'cidr': "192.1.1.1/2"},
                       status="*")

        self.assertEqual(duplicate_block_response.status, "400 Bad Request")
        self.assertTrue("cidr for public ip is not unique"
                        in duplicate_block_response.body)


class TestPrivateIpBlockController(IpBlockControllerBase, BaseTestController):

    def setUp(self):
        self.ip_block_path = "/ipam/tenants/123/private_ip_blocks"
        super(TestPrivateIpBlockController, self).setUp()

    def _ip_block_factory(self, **kwargs):
        return PrivateIpBlockFactory(tenant_id=123, **kwargs)

    def test_create(self):
        response = self.app.post("/ipam/tenants/111/private_ip_blocks.json",
                                 {'network_id': "300", 'cidr': "10.1.1.0/2"})

        self.assertEqual(response.status, "201 Created")
        saved_block = IpBlock.find_by_network_id("300")
        self.assertEqual(saved_block.cidr, "10.1.1.0/2")
        self.assertEqual(saved_block.type, "private")
        self.assertEqual(saved_block.tenant_id, "111")
        self.assertEqual(response.json, dict(ip_block=saved_block.data()))

    def test_create_ignores_tenant_id_passed_in_post_body(self):
        response = self.app.post("/ipam/tenants/111/private_ip_blocks",
                                 {'network_id': "300", 'cidr': "10.1.1.0/2",
                                  'tenant_id': "543"})

        saved_block = IpBlock.find_by_network_id("300")
        self.assertEqual(saved_block.tenant_id, "111")
        self.assertEqual(response.json, dict(ip_block=saved_block.data()))

    def test_show_fails_if_block_doenst_belong_to_tenant(self):
        block = PrivateIpBlockFactory(tenant_id='0000')
        response = self.app.get("/ipam/tenants/112/private_ip_blocks/%s"
                                % block.id, status='*')

        self.assertEqual(response.status, "404 Not Found")

    def test_index_scoped_by_tenant(self):
        ip_block1 = PrivateIpBlockFactory(cidr="10.0.0.1/8", tenant_id='999')
        ip_block2 = PrivateIpBlockFactory(cidr="10.0.0.2/8", tenant_id='999')
        PrivateIpBlockFactory(cidr="10.1.1.1/2", tenant_id='987')

        response = self.app.get("/ipam/tenants/999/private_ip_blocks")

        self.assertEqual(response.status, "200 OK")
        response_blocks = response.json['ip_blocks']
        self.assertEqual(len(response_blocks), 2)
        self.assertEqual(response_blocks, _data_of(ip_block1, ip_block2))


class IpAddressControllerBase():

    def test_create(self):
        block = self.ip_block_factory(cidr="10.1.1.0/28", tenant_id=111)
        response = self.app.post("/ipam/tenants/111/private_ip_blocks"
                                 "/%s/ip_addresses" % block.id)

        self.assertEqual(response.status, "201 Created")
        allocated_address = IpAddress.find_all_by_ip_block(block.id).first()
        self.assertEqual(allocated_address.address, "10.1.1.0")
        self.assertEqual(response.json,
                         dict(ip_address=allocated_address.data()))

    def test_create_with_given_address(self):
        block = self.ip_block_factory(cidr="10.1.1.0/28", tenant_id=111)
        response = self.app.post("/ipam/tenants/111/"
                                 "private_ip_blocks/%s/ip_addresses"
                                 % block.id,
                                 {"address": '10.1.1.2'})

        self.assertEqual(response.status, "201 Created")
        self.assertNotEqual(IpAddress.find_by_block_and_address(block.id,
                                                             "10.1.1.2"), None)

    def test_create_when_no_more_addresses(self):
        block = self.ip_block_factory(cidr="10.1.1.0/32", tenant_id="111")
        block.allocate_ip()

        response = self.app.post("/ipam/tenants/111/private_ip_blocks"
                                 "/%s/ip_addresses" % block.id,
                                 status="*")
        self.assertEqual(response.status, "422 Unprocessable Entity")
        self.assertTrue("IpBlock is full" in response.body)

    def test_create_fails_when_addresses_are_duplicated(self):
        block = self.ip_block_factory(cidr="10.1.1.0/29", tenant_id="111")
        block.allocate_ip(address='10.1.1.2')

        response = self.app.post("/ipam/tenants/111/private_ip_blocks"
                                 "/%s/ip_addresses" % block.id,
                                 {'address': '10.1.1.2'},
                                 status="*")
        self.assertEqual(response.status, "422 Unprocessable Entity")
        self.assertTrue("Address is already allocated" in response.body)

    def test_create_fails_when_address_doesnt_belong_to_block(self):
        block = self.ip_block_factory(cidr="10.1.1.0/32", tenant_id="111")

        response = self.app.post("/ipam/tenants/111/private_ip_blocks/%s"
                                 "/ip_addresses" % block.id,
                                 {'address': '10.1.1.2'},
                                 status="*")
        self.assertEqual(response.status, "422 Unprocessable Entity")
        self.assertTrue("Address does not belong to IpBlock" in response.body)

    def test_create_with_port(self):
        block = self.ip_block_factory(tenant_id="111")

        self.app.post("/ipam/tenants/111/private_ip_blocks/"
                      "%s/ip_addresses" % block.id,
                                 {"port_id": "1111"})

        allocated_address = IpAddress.find_all_by_ip_block(block.id).first()
        self.assertEqual(allocated_address.port_id, "1111")

    def test_show(self):
        block_1 = self.ip_block_factory(cidr='10.1.1.1/30', tenant_id="111")
        block_2 = self.ip_block_factory(cidr='10.2.2.2/30', tenant_id="333")
        ip = block_1.allocate_ip(port_id="3333")
        block_2.allocate_ip(port_id="9999")

        response = self.app.get("/ipam/tenants/111/private_ip_blocks/"
                                "%s/ip_addresses/%s" %
                                (block_1.id, ip.address))

        self.assertEqual(response.status, "200 OK")
        self.assertEqual(response.json, dict(ip_address=ip.data()))

    def test_show_fails_for_nonexistent_address(self):
        block = self.ip_block_factory(cidr="10.1.1.0/28", tenant_id="111")

        response = self.app.get("/ipam/tenants/111/private_ip_blocks/"
                                "%s/ip_addresses/%s" %
                                (block.id, '10.1.1.0'), status="*")

        self.assertEqual(response.status, "404 Not Found")
        self.assertTrue("IpAddress Not Found" in response.body)

    def test_show_fails_for_nonexistent_block(self):
        response = self.app.get("/ipam/tenants/111/private_ip_blocks/"
                                "%s/ip_addresses/%s" %
                                (1111111111, '10.1.1.0'), status="*")

        self.assertEqual(response.status, "404 Not Found")
        self.assertTrue("IpBlock Not Found" in response.body)

    def test_delete_ip(self):
        block_1 = self.ip_block_factory(cidr='10.1.1.1/30', tenant_id="111")
        block_2 = self.ip_block_factory(cidr='10.2.2.2/30')
        ip = block_1.allocate_ip()
        block_2.allocate_ip()

        response = self.app.delete("/ipam/tenants/111/private_ip_blocks/"
                                   "%s/ip_addresses/%s" %
                                (block_1.id, ip.address))

        self.assertEqual(response.status, "200 OK")
        self.assertNotEqual(IpAddress.find(ip.id), None)
        self.assertTrue(IpAddress.find(ip.id).marked_for_deallocation)

    def test_index(self):
        block = self.ip_block_factory(tenant_id="111")
        address_1 = block.allocate_ip()
        address_2 = block.allocate_ip()

        response = self.app.get("/ipam/tenants/111/private_ip_blocks/"
                                "%s/ip_addresses" % block.id)

        ip_addresses = response.json["ip_addresses"]
        self.assertEqual(response.status, "200 OK")
        self.assertEqual(len(ip_addresses), 2)
        self.assertEqual(ip_addresses[0]['address'], address_1.address)
        self.assertEqual(ip_addresses[1]['address'], address_2.address)

    def test_index_with_pagination(self):
        block = self.ip_block_factory(tenant_id="111")
        ips = [block.allocate_ip() for i in range(5)]

        response = self.app.get("/ipam/tenants/111/private_ip_blocks/"
                                "%s/ip_addresses?"
                                "limit=2&marker=%s" % (block.id, ips[1].id))

        ip_addresses = response.json["ip_addresses"]
        self.assertEqual(len(ip_addresses), 2)
        self.assertEqual(ip_addresses[0]['address'], ips[2].address)
        self.assertEqual(ip_addresses[1]['address'], ips[3].address)

    def test_restore_deallocated_ip(self):
        block = self.ip_block_factory(tenant_id="111")
        ips = [block.allocate_ip() for i in range(5)]
        block.deallocate_ip(ips[0].address)

        response = self.app.put("/ipam/tenants/111/private_ip_blocks/"
                                "%s/ip_addresses/"
                                "%s/restore" % (block.id, ips[0].address))

        ip_addresses = [ip.address for ip in
                        IpAddress.find_all_by_ip_block(block.id)]
        self.assertEqual(response.status, "200 OK")
        self.assertEqual(ip_addresses, [ip.address for ip in ips])


class TestPrivateIpAddressController(IpAddressControllerBase,
                                     BaseTestController):

    def setUp(self):
        self.ip_block_factory = PrivateIpBlockFactory
        super(TestPrivateIpAddressController, self).setUp()


class TestPublicIpAddressController(IpAddressControllerBase,
                                     BaseTestController):

    def setUp(self):
        self.ip_block_factory = PublicIpBlockFactory
        super(TestPublicIpAddressController, self).setUp()


class TestInsideGlobalsController(BaseTestController):

    def test_index(self):
        local_block, global_block_1, global_block_2 =\
                                    _create_blocks("10.1.1.1/30",
                                                        "192.1.1.1/30",
                                                        "169.1.1.1/30")
        [local_ip], [global_ip_1], [global_ip_2] =\
                                    _allocate_ips((local_block, 1),
                                                       (global_block_1, 1),
                                                       (global_block_2, 1))
        local_ip.add_inside_globals([global_ip_1, global_ip_2])

        response = self.app.get("/ipam/ip_blocks/%s/ip_addresses/%s/"
                                "inside_globals"
                                 % (local_block.id, local_ip.address))

        self.assertEqual(response.json,
                         {'ip_addresses': _data_of(global_ip_1,
                                                   global_ip_2)})

    def test_index_with_pagination(self):
        local_block, global_block = _create_blocks("10.1.1.1/8",
                                                   "192.1.1.1/8")
        [local_ip], global_ips = _allocate_ips((local_block, 1),
                                               (global_block, 5))
        local_ip.add_inside_globals(global_ips)

        response = self.app.get("/ipam/ip_blocks/%s/ip_addresses/%s/"
                                "inside_globals?limit=2&marker=%s"
                                % (local_block.id, local_ip.address,
                                   global_ips[1].id))

        self.assertEqual(response.json,
                        {'ip_addresses': _data_of(global_ips[2],
                                                  global_ips[3])})

    def test_index_for_nonexistent_block(self):
        non_existant_block_id = 12122
        url = "/ipam/ip_blocks/%s/ip_addresses/%s/inside_globals"
        response = self.app.get(url % (non_existant_block_id,
                                       "10.1.1.2"),
                                status='*')

        self.assertErrorResponse(response, "404 Not Found",
                                     "IpBlock Not Found")

    def test_index_for_nonexistent_address(self):
        ip_block, = _create_blocks("191.1.1.1/10")
        url = "/ipam/ip_blocks/%s/ip_addresses/%s/inside_globals"
        response = self.app.get(url % (ip_block.id, '10.1.1.2'),
                                status='*')

        self.assertErrorResponse(response, "404 Not Found",
                                     "IpAddress Not Found")

    def test_create(self):
        global_block, local_block = _create_blocks('192.1.1.1/32',
                                                        '10.1.1.1/32')
        global_ip = global_block.allocate_ip()
        local_ip = local_block.allocate_ip()

        response = self.app.post("/ipam/ip_blocks/%s/ip_addresses/%s/"
                                 "inside_globals"
                              % (local_block.id, local_ip.address),
                              {"ip_addresses": json.dumps(
                                [{"ip_block_id": global_block.id,
                                  "ip_address": global_ip.address}])})

        self.assertEqual(response.status, "200 OK")

        self.assertEqual(len(local_ip.inside_globals()), 1)
        self.assertEqual(global_ip.id, local_ip.inside_globals()[0].id)
        self.assertEqual(local_ip.id, global_ip.inside_locals()[0].id)

    def test_delete(self):
        global_block, local_block = _create_blocks('192.1.1.1/32',
                                                        '10.1.1.1/32')
        global_ip = global_block.allocate_ip()
        local_ip = local_block.allocate_ip()
        local_ip.add_inside_globals([global_ip])

        response = self.app.delete("/ipam/ip_blocks/%s/ip_addresses/%s/"
                                 "inside_globals"
                              % (local_block.id, local_ip.address))

        self.assertEqual(response.status, "200 OK")
        self.assertEqual(local_ip.inside_globals(), [])

    def test_delete_for_specific_address(self):
        global_block, local_block = _create_blocks('192.1.1.1/28',
                                                    '10.1.1.1/28')
        global_ips, = _allocate_ips((global_block, 3))
        local_ip = local_block.allocate_ip()
        local_ip.add_inside_globals(global_ips)

        self.app.delete("/ipam/ip_blocks/%s/ip_addresses/%s/"
                                 "inside_globals/%s"
                                   % (local_block.id, local_ip.address,
                                      global_ips[1].address))

        globals_left = [ip.address for ip in local_ip.inside_globals()]
        self.assertEqual(globals_left, [global_ips[0].address,
                                        global_ips[2].address])

    def test_delete_for_nonexistent_block(self):
        non_existant_block_id = 12122
        url = "/ipam/ip_blocks/%s/ip_addresses/%s/inside_globals"
        response = self.app.delete(url % (non_existant_block_id,
                                          '10.1.1.2'), status='*')

        self.assertErrorResponse(response, "404 Not Found",
                                     "IpBlock Not Found")

    def test_delete_for_nonexistent_address(self):
        ip_block, = _create_blocks("191.1.1.1/10")
        url = "/ipam/ip_blocks/%s/ip_addresses/%s/inside_globals"
        response = self.app.delete(url % (ip_block.id, '10.1.1.2'),
                                    status='*')

        self.assertErrorResponse(response, "404 Not Found",
                                     "IpAddress Not Found")


class TestInsideLocalsController(BaseTestController):

    def test_index(self):
        global_block, local_block = _create_blocks("192.1.1.1/8",
                                                   "10.1.1.1/8")
        [global_ip], local_ips = _allocate_ips((global_block, 1),
                                               (local_block, 5))
        global_ip.add_inside_locals(local_ips)

        response = self.app.get("/ipam/ip_blocks/%s/ip_addresses/%s/"
                                "inside_locals"
                                % (global_block.id, global_ip.address))

        self.assertEqual(response.json,
                         {'ip_addresses': _data_of(*local_ips)})

    def test_index_with_pagination(self):
        global_block, local_block = _create_blocks("192.1.1.1/8",
                                                        "10.1.1.1/8")
        [global_ip], local_ips = _allocate_ips((global_block, 1),
                                                    (local_block, 5))
        global_ip.add_inside_locals(local_ips)

        response = self.app.get("/ipam/ip_blocks/%s/ip_addresses/%s/"
                                "inside_locals?limit=2&marker=%s"
                                % (global_block.id,
                                   global_ip.address,
                                   local_ips[1].id))

        self.assertEqual(response.json,
                         {'ip_addresses': _data_of(local_ips[2],
                                                   local_ips[3])})

    def test_index_for_nonexistent_block(self):
        non_existant_block_id = 12122
        url = "/ipam/ip_blocks/%s/ip_addresses/%s/inside_locals"
        response = self.app.get(url % (non_existant_block_id,
                                       "10.1.1.2"),
                                status='*')

        self.assertErrorResponse(response, "404 Not Found",
                                 "IpBlock Not Found")

    def test_index_for_nonexistent_address(self):
        ip_block, = _create_blocks("191.1.1.1/10")
        url = "/ipam/ip_blocks/%s/ip_addresses/%s/inside_locals"
        response = self.app.get(url % (ip_block.id, '10.1.1.2'),
                                status='*')

        self.assertErrorResponse(response, "404 Not Found",
                                     "IpAddress Not Found")

    def test_create(self):
        global_block, = _create_blocks("169.1.1.1/32")
        local_block1, = _create_blocks("10.1.1.1/32")
        local_block2, = _create_blocks("10.0.0.1/32")

        url = "/ipam/ip_blocks/%s/ip_addresses/169.1.1.1/inside_locals"
        json_data = [
            {'ip_block_id': local_block1.id, 'ip_address': "10.1.1.1"},
            {'ip_block_id': local_block2.id, 'ip_address': "10.0.0.1"},
        ]
        request_data = {'ip_addresses': json.dumps(json_data)}
        response = self.app.post(url % global_block.id, request_data)

        self.assertEqual(response.status, "200 OK")
        ips = global_block.find_allocated_ip("169.1.1.1").inside_locals()
        inside_locals = [ip.address for ip in ips]

        self.assertEqual(len(inside_locals), 2)
        self.assertTrue("10.1.1.1" in inside_locals)
        self.assertTrue("10.0.0.1" in inside_locals)
        local_ip = IpAddress.find_by_block_and_address(local_block1.id,
                                                       "10.1.1.1")
        self.assertEqual(local_ip.inside_globals()[0].address, "169.1.1.1")

    def test_delete_for_specific_address(self):
        global_block, local_block = _create_blocks('192.1.1.1/28',
                                                    '10.1.1.1/28')
        local_ips, = _allocate_ips((local_block, 3))
        global_ip = global_block.allocate_ip()
        global_ip.add_inside_locals(local_ips)

        self.app.delete("/ipam/ip_blocks/%s/ip_addresses/%s/"
                                 "inside_locals/%s"
                                   % (global_block.id, global_ip.address,
                                      local_ips[1].address))

        locals_left = [ip.address for ip in global_ip.inside_locals()]
        self.assertEqual(locals_left, [local_ips[0].address,
                                        local_ips[2].address])

    def test_delete(self):
        global_block, local_block = _create_blocks('192.1.1.1/32',
                                                        '10.1.1.1/32')
        global_ip = global_block.allocate_ip()
        local_ip = local_block.allocate_ip()
        global_ip.add_inside_locals([local_ip])

        response = self.app.delete("/ipam/ip_blocks/%s/ip_addresses/%s/"
                                 "inside_locals"
                              % (global_block.id, global_ip.address))

        self.assertEqual(response.status, "200 OK")
        self.assertEqual(global_ip.inside_locals(), [])

    def test_delete_for_nonexistent_block(self):
        non_existant_block_id = 12122
        url = "/ipam/ip_blocks/%s/ip_addresses/%s/inside_locals"
        response = self.app.delete(url % (non_existant_block_id,
                                          '10.1.1.2'), status='*')

        self.assertErrorResponse(response, "404 Not Found",
                                     "IpBlock Not Found")

    def test_delete_for_nonexistent_address(self):
        ip_block, = _create_blocks("191.1.1.1/10")
        url = "/ipam/ip_blocks/%s/ip_addresses/%s/inside_locals"
        response = self.app.delete(url % (ip_block.id, '10.1.1.2'),
                                   status='*')

        self.assertErrorResponse(response, "404 Not Found",
                                 "IpAddress Not Found")


class UnusableIpRangesControllerBase():

    def test_create(self):
        policy = self._policy_factory()

        response = self.app.post("%s/%s/unusable_ip_ranges"
                                 % (self.policy_path, policy.id),
                                 {'offset': '10', 'length': '2'})

        unusable_range = IpRange.find_all_by_policy(policy.id).first()
        self.assertEqual(response.status, "201 Created")
        self.assertEqual(response.json, dict(ip_range=unusable_range.data()))

    def test_create_on_non_existent_policy(self):
        response = self.app.post("%s/10000/unusable_ip_ranges"
                                 % self.policy_path,
                                 {'offset': '1', 'length': '2'}, status="*")

        self.assertErrorResponse(response, "404 Not Found",
                                 "Policy Not Found")

    def test_show(self):
        policy = self._policy_factory()
        ip_range = IpRangeFactory.create(policy_id=policy.id)

        response = self.app.get("%s/%s/unusable_ip_ranges/%s"
                                % (self.policy_path, policy.id, ip_range.id))

        self.assertEqual(response.status_int, 200)
        self.assertEqual(response.json, dict(ip_range=ip_range.data()))

    def test_show_when_ip_range_does_not_exists(self):
        policy = self._policy_factory()

        response = self.app.get("%s/%s/unusable_ip_ranges/%s"
                                % (self.policy_path, policy.id, 1000000),
                                status="*")

        self.assertErrorResponse(response, "404 Not Found",
                                  "Can't find IpRange for policy")

    def test_update(self):
        policy = self._policy_factory()
        ip_range = IpRangeFactory.create(offset=10, length=11,
                                         policy_id=policy.id)

        response = self.app.put("%s/%s/unusable_ip_ranges/%s"
                                % (self.policy_path, policy.id, ip_range.id),
                                {'offset': 1111, 'length': 2222})

        self.assertEqual(response.status_int, 200)
        updated_range = IpRange.find(ip_range.id)
        self.assertEqual(updated_range.offset, 1111)
        self.assertEqual(updated_range.length, 2222)
        self.assertEqual(response.json, dict(ip_range=updated_range.data()))

    def test_update_ignores_change_in_policy_id(self):
        policy = self._policy_factory()
        ip_range = IpRangeFactory.create(offset=10, length=11,
                                         policy_id=policy.id)
        new_policy_id = policy.id + 1
        response = self.app.put("%s/%s/unusable_ip_ranges/%s"
                                % (self.policy_path, policy.id, ip_range.id),
                                {'offset': 1111, 'length': 2222,
                                'policy_id': new_policy_id})

        self.assertEqual(response.status_int, 200)
        updated_range = IpRange.find(ip_range.id)
        self.assertEqual(updated_range.policy_id, policy.id)
        self.assertEqual(response.json['ip_range']['policy_id'], policy.id)

    def test_update_when_ip_range_does_not_exists(self):
        policy = self._policy_factory()

        response = self.app.put("%s/%s/unusable_ip_ranges/%s"
                                 % (self.policy_path, policy.id, "invalid_id"),
                                 {'offset': 1111, 'length': 222}, status="*")

        self.assertErrorResponse(response, "404 Not Found",
                                  "Can't find IpRange for policy")

    def test_index(self):
        policy = self._policy_factory()
        for i in range(0, 3):
            IpRangeFactory(policy_id=policy.id)

        response = self.app.get("%s/%s/unusable_ip_ranges"
                                 % (self.policy_path, policy.id))

        response_ranges = response.json["ip_ranges"]
        self.assertEqual(len(response_ranges), 3)
        self.assertEqual(response_ranges,
                         _data_of(*policy.unusable_ip_ranges))

    def test_delete(self):
        policy = self._policy_factory()
        ip_range = IpRangeFactory(policy_id=policy.id)

        response = self.app.delete("%s/%s/unusable_ip_ranges/%s"
                                 % (self.policy_path, policy.id, ip_range.id))

        self.assertEqual(response.status_int, 200)
        self.assertRaises(models.ModelNotFoundError,
                          policy.find_ip_range, ip_range_id=ip_range.id)


class TestUnusableIpRangeControllerForStandardPolicies(
    UnusableIpRangesControllerBase, BaseTestController):

    def setUp(self):
        self.policy_path = "/ipam/policies"
        super(TestUnusableIpRangeControllerForStandardPolicies, self).setUp()

    def _policy_factory(self, **kwargs):
        return PolicyFactory(**kwargs)


class TestUnusableIpRangeControllerForTenantPolicies(
    UnusableIpRangesControllerBase, BaseTestController):

    def setUp(self):
        self.policy_path = "/ipam/tenants/123/policies"
        super(TestUnusableIpRangeControllerForTenantPolicies, self).setUp()

    def _policy_factory(self, **kwargs):
        return PolicyFactory(tenant_id="123", **kwargs)

    def test_show_fails_for_non_existent_policy_for_given_tenant(self):
        policy = PolicyFactory(tenant_id=123)
        ip_range = IpRangeFactory(policy_id=policy.id)
        self.policy_path = "/ipam/tenants/111/policies"
        response = self.app.get("%s/%s/unusable_ip_ranges/%s"
                                 % (self.policy_path, policy.id, ip_range.id),
                                status='*')

        self.assertEqual(response.status_int, 404)

    def test_index_fails_for_non_existent_policy_for_given_tenant(self):
        policy = PolicyFactory(tenant_id=123)
        ip_range = IpRangeFactory(policy_id=policy.id)
        self.policy_path = "/ipam/tenants/111/policies"
        response = self.app.get("%s/%s/unusable_ip_ranges"
                                 % (self.policy_path, policy.id),
                                 status='*')

        self.assertEqual(response.status_int, 404)

    def test_create_fails_for_non_existent_policy_for_given_tenant(self):
        policy = PolicyFactory(tenant_id=123)
        ip_range = IpRangeFactory(policy_id=policy.id)
        self.policy_path = "/ipam/tenants/111/policies"
        response = self.app.post("%s/%s/unusable_ip_ranges"
                                 % (self.policy_path, policy.id),
                                 {'offset': 1, 'length': 20},
                                 status='*')

        self.assertEqual(response.status_int, 404)

    def test_update_fails_for_non_existent_policy_for_given_tenant(self):
        policy = PolicyFactory(tenant_id=123)
        ip_range = IpRangeFactory(policy_id=policy.id)
        self.policy_path = "/ipam/tenants/111/policies"
        response = self.app.put("%s/%s/unusable_ip_ranges/%s"
                                 % (self.policy_path, policy.id, ip_range.id),
                                 {'offset': 1}, status='*')

        self.assertEqual(response.status_int, 404)

    def test_delete_fails_for_non_existent_policy_for_given_tenant(self):
        policy = PolicyFactory(tenant_id=123)
        ip_range = IpRangeFactory(policy_id=policy.id)
        self.policy_path = "/ipam/tenants/111/policies"
        response = self.app.delete("%s/%s/unusable_ip_ranges/%s"
                                 % (self.policy_path, policy.id, ip_range.id),
                                 status='*')

        self.assertEqual(response.status_int, 404)


class UnusableIpOctetsControllerBase():

    def test_index(self):
        policy = self._policy_factory()
        for i in range(0, 3):
            IpOctetFactory(policy_id=policy.id)

        response = self.app.get("%s/%s/unusable_ip_octets"
                                 % (self.policy_path, policy.id))

        response_octets = response.json["ip_octets"]
        self.assertEqual(len(response_octets), 3)
        self.assertEqual(response_octets,
                         _data_of(*policy.unusable_ip_octets))

    def test_index_with_limits(self):
        policy = self._policy_factory()
        for i in range(0, 3):
            IpOctetFactory(policy_id=policy.id)

        response = self.app.get("%s/%s/unusable_ip_octets"
                                 % (self.policy_path, policy.id), {'limit': 2})

        response_octets = response.json["ip_octets"]
        self.assertEqual(len(response_octets), 2)

    def test_create(self):
        policy = self._policy_factory()
        response = self.app.post("%s/%s/unusable_ip_octets"
                                 % (self.policy_path, policy.id),
                                 {'octet': '123'})

        ip_octet = IpOctet.find_all_by_policy(policy.id).first()
        self.assertEqual(response.status, "201 Created")
        self.assertEqual(response.json['ip_octet'], ip_octet.data())

    def test_create_on_non_existent_policy(self):
        response = self.app.post("%s/10000/unusable_ip_octets"
                                 % self.policy_path,
                                 {'octet': '2'}, status="*")

        self.assertErrorResponse(response, "404 Not Found",
                                 "Policy Not Found")

    def test_show(self):
        policy = self._policy_factory()
        ip_octet = IpOctetFactory(policy_id=policy.id)

        response = self.app.get("%s/%s/unusable_ip_octets/%s"
                                 % (self.policy_path, policy.id, ip_octet.id))

        self.assertEqual(response.status_int, 200)
        self.assertEqual(response.json['ip_octet'], ip_octet.data())

    def test_show_when_ip_octet_does_not_exists(self):
        policy = self._policy_factory()

        response = self.app.get("%s/%s/unusable_ip_octets/%s"
                                % (self.policy_path, policy.id, 1000000),
                                status="*")

        self.assertErrorResponse(response, "404 Not Found",
                                  "Can't find IpOctet for policy")

    def test_update(self):
        policy = self._policy_factory()
        ip_octet = IpOctetFactory.create(octet=10, policy_id=policy.id)

        response = self.app.put("%s/%s/unusable_ip_octets/%s"
                                % (self.policy_path, policy.id, ip_octet.id),
                                {'octet': 123})

        self.assertEqual(response.status_int, 200)
        updated_octet = IpOctet.find(ip_octet.id)
        self.assertEqual(updated_octet.octet, 123)
        self.assertEqual(response.json['ip_octet'], updated_octet.data())

    def test_update_ignores_change_in_policy_id(self):
        policy = self._policy_factory()
        ip_octet = IpOctetFactory.create(octet=254, policy_id=policy.id)
        new_policy_id = policy.id + 1
        response = self.app.put("%s/%s/unusable_ip_octets/%s"
                                % (self.policy_path, policy.id, ip_octet.id),
                                {'octet': 253, 'policy_id': new_policy_id})

        self.assertEqual(response.status_int, 200)
        updated_octet = IpOctet.find(ip_octet.id)
        self.assertEqual(updated_octet.policy_id, policy.id)
        self.assertEqual(response.json['ip_octet']['policy_id'], policy.id)

    def test_update_when_ip_octet_does_not_exists(self):
        policy = self._policy_factory()

        response = self.app.put("%s/%s/unusable_ip_octets/%s"
                                 % (self.policy_path, policy.id, "invalid_id"),
                                 {'octet': 222}, status="*")

        self.assertErrorResponse(response, "404 Not Found",
                                  "Can't find IpOctet for policy")

    def test_delete(self):
        policy = self._policy_factory()
        ip_octet = IpOctetFactory(policy_id=policy.id)

        response = self.app.delete("%s/%s/unusable_ip_octets/%s"
                                 % (self.policy_path, policy.id, ip_octet.id))

        self.assertEqual(response.status_int, 200)
        self.assertRaises(models.ModelNotFoundError,
                          policy.find_ip_octet, ip_octet_id=ip_octet.id)


class TestUnusableIpOctetControllerForStandardPolicies(
    UnusableIpOctetsControllerBase, BaseTestController):

    def setUp(self):
        self.policy_path = "/ipam/policies"
        super(TestUnusableIpOctetControllerForStandardPolicies, self).setUp()

    def _policy_factory(self, **kwargs):
        return PolicyFactory(**kwargs)


class TestUnusableIpOctetControllerForTenantPolicies(
    UnusableIpOctetsControllerBase, BaseTestController):

    def setUp(self):
        self.policy_path = "/ipam/tenants/123/policies"
        super(TestUnusableIpOctetControllerForTenantPolicies, self).setUp()

    def _policy_factory(self, **kwargs):
        return PolicyFactory(tenant_id="123", **kwargs)

    def test_show_fails_for_non_existent_policy_for_given_tenant(self):
        policy = PolicyFactory(tenant_id=123)
        ip_octet = IpOctetFactory(policy_id=policy.id)
        self.policy_path = "/ipam/tenants/111/policies"
        response = self.app.get("%s/%s/unusable_ip_octets/%s"
                                 % (self.policy_path, policy.id, ip_octet.id),
                                status='*')

        self.assertEqual(response.status_int, 404)

    def test_index_fails_for_non_existent_policy_for_given_tenant(self):
        policy = PolicyFactory(tenant_id=123)
        ip_octet = IpOctetFactory(policy_id=policy.id)
        self.policy_path = "/ipam/tenants/111/policies"
        response = self.app.get("%s/%s/unusable_ip_octets"
                                 % (self.policy_path, policy.id),
                                 status='*')

        self.assertEqual(response.status_int, 404)

    def test_create_fails_for_non_existent_policy_for_given_tenant(self):
        policy = PolicyFactory(tenant_id=123)
        ip_octet = IpOctetFactory(policy_id=policy.id)
        self.policy_path = "/ipam/tenants/111/policies"
        response = self.app.post("%s/%s/unusable_ip_octets"
                                 % (self.policy_path, policy.id),
                                 {'octet': 1},
                                 status='*')

        self.assertEqual(response.status_int, 404)

    def test_update_fails_for_non_existent_policy_for_given_tenant(self):
        policy = PolicyFactory(tenant_id=123)
        ip_octet = IpOctetFactory(policy_id=policy.id)
        self.policy_path = "/ipam/tenants/111/policies"
        response = self.app.put("%s/%s/unusable_ip_octets/%s"
                                 % (self.policy_path, policy.id, ip_octet.id),
                                 {'octet': 1}, status='*')

        self.assertEqual(response.status_int, 404)

    def test_delete_fails_for_non_existent_policy_for_given_tenant(self):
        policy = PolicyFactory(tenant_id=123)
        ip_octet = IpOctetFactory(policy_id=policy.id)
        self.policy_path = "/ipam/tenants/111/policies"
        response = self.app.delete("%s/%s/unusable_ip_octets/%s"
                                 % (self.policy_path, policy.id, ip_octet.id),
                                 status='*')

        self.assertEqual(response.status_int, 404)


class TestPoliciesController(BaseTestController):

    def test_create(self):
        response = self.app.post("/ipam/policies", {'name': "infrastructure"})

        self.assertTrue(Policy.find_by(name="infrastructure") is not None)
        self.assertEqual(response.status, "201 Created")
        self.assertEqual(response.json['policy']['name'], "infrastructure")

    def test_index(self):
        PolicyFactory(name="infrastructure")
        PolicyFactory(name="unstable")

        response = self.app.get("/ipam/policies")

        self.assertEqual(response.status, "200 OK")
        response_policies = response.json['policies']
        policies = Policy.find_all().all()
        self.assertEqual(len(policies), 2)
        self.assertEqual(response_policies, _data_of(*policies))

    def test_show_when_requested_policy_exists(self):
        policy = PolicyFactory(name="DRAC")

        response = self.app.get("/ipam/policies/%s" % policy.id)

        self.assertEqual(response.status, "200 OK")
        self.assertEqual(response.json, dict(policy=policy.data()))

    def test_show_when_requested_policy_does_not_exist(self):
        response = self.app.get("/ipam/policies/invalid_id", status="*")

        self.assertErrorResponse(response, "404 Not Found",
                                 "Policy Not Found")

    def test_update(self):
        policy = PolicyFactory(name="DRAC", description='description')

        response = self.app.put("/ipam/policies/%s" % policy.id,
                                {'name': "Updated Name",
                                 'description': "Updated Des"})

        self.assertEqual(response.status, "200 OK")
        updated_policy = Policy.find(policy.id)
        self.assertEqual(updated_policy.name, "Updated Name")
        self.assertEqual(updated_policy.description, "Updated Des")
        self.assertEqual(response.json, dict(policy=updated_policy.data()))

    def test_update_fails_for_invalid_policy_id(self):
        response = self.app.put("/ipam/policies/invalid",
                                {'name': "Updated Name"}, status="*")

        self.assertErrorResponse(response, "404 Not Found",
                                 "Policy Not Found")

    def test_delete(self):
        policy = PolicyFactory()
        response = self.app.delete("/ipam/policies/%s" % policy.id)

        self.assertEqual(response.status, "200 OK")


class TestTenantPoliciesController(BaseTestController):

    def test_index(self):
        policy1 = PolicyFactory(tenant_id="1")
        policy2 = PolicyFactory(tenant_id="2")
        policy3 = PolicyFactory(tenant_id="1")

        response = self.app.get("/ipam/tenants/1/policies")

        self.assertEqual(response.status_int, 200)
        self.assertEqual(response.json["policies"], _data_of(policy1, policy3))

    def test_create(self):
        response = self.app.post("/ipam/tenants/1111/policies",
                                 {'name': "infrastructure"})

        self.assertTrue(Policy.find_by(tenant_id="1111") is not None)
        self.assertEqual(response.status, "201 Created")
        self.assertEqual(response.json['policy']['tenant_id'], "1111")

    def test_create_ignores_tenant_id_passed_in_post_body(self):
        response = self.app.post("/ipam/tenants/123/policies",
                                {'name': "Standard", 'tenant_id': "124"})

        self.assertEqual(response.status_int, 201)
        self.assertEqual(response.json['policy']['name'], "Standard")
        self.assertEqual(response.json['policy']['tenant_id'], "123")

    def test_show(self):
        policy = PolicyFactory(tenant_id="1111")
        response = self.app.get("/ipam/tenants/1111/policies/%s" % policy.id)

        self.assertEqual(response.status, "200 OK")
        self.assertEqual(response.json['policy']['id'], policy.id)

    def test_show_fails_for_nonexistent_tenant(self):
        policy = PolicyFactory(tenant_id="1112")
        response = self.app.get("/ipam/tenants/1111/policies/%s" % policy.id,
                                status="*")

        self.assertEqual(response.status_int, 404)

    def test_update_fails_for_incorrect_tenant_id(self):
        policy = PolicyFactory(tenant_id="111")
        response = self.app.put("/ipam/tenants/123/policies/%s" % policy.id,
                                {'name': "Standard"}, status="*")

        self.assertEqual(response.status_int, 404)

    def test_update(self):
        policy = PolicyFactory(name="blah", tenant_id="123")
        response = self.app.put("/ipam/tenants/123/policies/%s" % policy.id,
                                {'name': "Standard"})

        self.assertEqual(response.status_int, 200)
        self.assertEqual("Standard", Policy.find(policy.id).name)

    def test_update_cannot_change_tenant_id(self):
        policy = PolicyFactory(name="Infrastructure", tenant_id="123")
        response = self.app.put("/ipam/tenants/123/policies/%s" % policy.id,
                                {'name': "Standard", 'tenant_id': "124"})

        self.assertEqual(response.status_int, 200)
        updated_policy = Policy.find(policy.id)
        self.assertEqual(updated_policy.name, "Standard")
        self.assertEqual(updated_policy.tenant_id, "123")
        self.assertEqual(response.json['policy']['tenant_id'], "123")

    def test_delete(self):
        policy = PolicyFactory(tenant_id="123")
        response = self.app.delete("/ipam/tenants/123/policies/%s" % policy.id)

        self.assertEqual(response.status_int, 200)
        self.assertTrue(Policy.find_by_id(policy.id) is None)

    def test_delete_fails_for_incorrect_tenant_id(self):
        policy = PolicyFactory(tenant_id="123")
        response = self.app.delete("/ipam/tenants/111/policies/%s" % policy.id,
                                   status="*")

        self.assertEqual(response.status_int, 404)


def _allocate_ips(*args):
    return [[ip_block.allocate_ip() for i in range(num_of_ips)]
            for ip_block, num_of_ips in args]


def _create_blocks(*args):
    return [PrivateIpBlockFactory(cidr=cidr) for cidr in args]


def _data_of(*args):
    return [model.data() for model in args]
