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

import routes
import string
import unittest
import webob.exc

from melange import ipv6
from melange import tests
from melange.common import config
from melange.common import exception
from melange.common import utils
from melange.common import wsgi
from melange.ipam import models
from melange.ipam import service
from melange.tests import unit
from melange.tests.factories import models as factory_models
from melange.tests.unit import mock_generator


class BaseTestController(tests.BaseTest):

    def setUp(self):
        super(BaseTestController, self).setUp()
        conf, melange_app = config.Config.load_paste_app('melange',
                {"config_file": unit.test_config_path()}, None)
        self.app = unit.TestApp(melange_app)


class DummyApp(wsgi.Router):

    def __init__(self):
        mapper = routes.Mapper()
        mapper.resource("resource", "/resources",
                                controller=StubController().create_resource())
        super(DummyApp, self).__init__(mapper)


class StubController(service.BaseController):
    def index(self, request):
        raise self.exception


class TestBaseController(unittest.TestCase):
    def _assert_mapping(self, exception, http_code):
        StubController.exception = exception
        app = unit.TestApp(DummyApp())

        response = app.get("/resources", status="*")
        self.assertEqual(response.status_int, http_code)

    def test_exception_to_http_code_mapping(self):
        self._assert_mapping(models.InvalidModelError(None), 400)
        self._assert_mapping(models.ModelNotFoundError, 404)
        self._assert_mapping(models.NoMoreAddressesError, 422)
        self._assert_mapping(models.AddressDoesNotBelongError, 422)
        self._assert_mapping(models.AddressLockedError, 422)
        self._assert_mapping(models.DuplicateAddressError, 409)
        self._assert_mapping(models.IpAddressConcurrentAllocationError, 409)
        self._assert_mapping(exception.ParamsMissingError, 400)

    def test_http_excpetions_are_bubbled_up(self):
        self._assert_mapping(webob.exc.HTTPUnprocessableEntity, 422)
        self._assert_mapping(webob.exc.HTTPNotFound, 404)


class TestIpBlockController(BaseTestController):

    def setUp(self):
        self.ip_block_path = "/ipam/tenants/tenant_id/ip_blocks"
        super(TestIpBlockController, self).setUp()

    def test_create_with_bad_cidr(self):
        response = self.app.post_json("%s" % self.ip_block_path,
                          {'ip_block': {'network_id': "300",
                                        'type': "public",
                                        'cidr': "10...",
                                        }
                           },
                          status="*")

        self.assertErrorResponse(response, webob.exc.HTTPBadRequest,
                                 'cidr is invalid')

    def test_create_ignores_uneditable_fields(self):
        response = self.app.post_json("%s" % self.ip_block_path,
                                 {'ip_block': {'network_id': "300",
                                               'cidr': "10.0.0.0/31",
                                               'type': "public",
                                               'parent_id': 'input_parent_id',
                                               'tenant_id': 'input_tenant_id',
                                               },
                                  },
                                 status="*")

        self.assertEqual(response.status_int, 201)
        created_block = models.IpBlock.find_by(network_id="300")
        self.assertNotEqual(created_block.type, "Ignored")
        self.assertNotEqual(created_block.parent_id, "input_parent_id")
        self.assertNotEqual(created_block.tenant_id, "input_tenant_id")

    def test_show(self):
        block = factory_models.IpBlockFactory()
        response = self.app.get("%s/%s" % (self.ip_block_path, block.id))

        self.assertEqual(response.status, "200 OK")
        self.assertEqual(response.json['ip_block'], _data(block))

    def test_update(self):
        old_policy = factory_models.PolicyFactory()
        new_policy = factory_models.PolicyFactory()
        block = factory_models.IpBlockFactory(network_id="net1",
                                              policy_id=old_policy.id)

        response = self.app.put_json("%s/%s" % (self.ip_block_path, block.id),
                                     {'ip_block': {
                                         'network_id': "new_net",
                                         'policy_id': new_policy.id,
                                         }
                                      })
        updated_block = models.IpBlock.find(block.id)
        self.assertEqual(response.status_int, 200)
        self.assertEqual(updated_block.network_id, "new_net")
        self.assertEqual(updated_block.policy_id, new_policy.id)

        self.assertEqual(response.json, dict(ip_block=_data(updated_block)))

    def test_update_to_exclude_uneditable_fields(self):
        parent = factory_models.IpBlockFactory(cidr="10.0.0.0/28")
        another = factory_models.IpBlockFactory(cidr="20.0.0.0/28")
        block = factory_models.IpBlockFactory(cidr="10.0.0.0/29",
                                              parent_id=parent.id)

        response = self.app.put_json("%s/%s" % (self.ip_block_path, block.id),
                                     {'ip_block': {
                                         'type': "new_type",
                                         'cidr': "50.0.0.0/29",
                                         'tenant_id': "new_tenant",
                                         'parent_id': another.id,
                                         }
                                      })
        updated_block = models.IpBlock.find(block.id)
        self.assertEqual(response.status_int, 200)
        self.assertEqual(updated_block.cidr, "10.0.0.0/29")
        self.assertNotEqual(updated_block.tenant_id, "new_tenant")
        self.assertNotEqual(updated_block.parent_id, another.id)
        self.assertNotEqual(updated_block.type, "new_type")

        self.assertEqual(response.json, dict(ip_block=_data(updated_block)))

    def test_delete(self):
        block = factory_models.IpBlockFactory()
        response = self.app.delete("%s/%s" % (self.ip_block_path, block.id))

        self.assertEqual(response.status, "200 OK")
        self.assertRaises(models.ModelNotFoundError,
                          models.IpBlock.find,
                          block.id)

    def test_index(self):
        blocks = [factory_models.PublicIpBlockFactory(cidr="192.1.1.1/30",
                                                      network_id="1"),
                  factory_models.PrivateIpBlockFactory(cidr="192.2.2.2/30",
                                                      network_id="2"),
                  factory_models.PublicIpBlockFactory(cidr="192.3.3.3/30",
                                                      network_id="1"),
                  ]
        response = self.app.get("%s" % self.ip_block_path)
        self.assertEqual(response.status, "200 OK")
        response_blocks = response.json['ip_blocks']
        self.assertEqual(len(response_blocks), 3)
        self.assertItemsEqual(response_blocks, _data(blocks))

    def test_index_is_able_to_filter_by_type(self):
        factory_models.PublicIpBlockFactory(cidr="72.1.1.1/30", network_id="1")
        private_factory = factory_models.PrivateIpBlockFactory
        private_blocks = [private_factory(cidr="12.2.2.2/30", network_id="2"),
                          private_factory(cidr="192.3.3.3/30", network_id="2"),
                          ]

        response = self.app.get("%s" % self.ip_block_path, {'type': "private"})

        self.assertEqual(response.status, "200 OK")
        response_blocks = response.json['ip_blocks']
        self.assertEqual(len(response_blocks), 2)
        self.assertItemsEqual(response_blocks, _data(private_blocks))

    def test_index_with_pagination(self):
        blocks = [factory_models.IpBlockFactory(cidr="10.1.1.0/28"),
                  factory_models.IpBlockFactory(cidr='10.2.1.0/28'),
                  factory_models.IpBlockFactory(cidr='10.3.1.0/28'),
                  factory_models.IpBlockFactory(cidr='10.4.1.0/28'),
                  factory_models.IpBlockFactory(cidr='10.5.1.0/28'),
                  ]

        blocks = models.sort(blocks)

        response = self.app.get("%s?limit=2&marker=%s" % (self.ip_block_path,
                                                          blocks[1].id))

        next_link = response.json["ip_blocks_links"][0]['href']
        response_blocks = response.json['ip_blocks']
        expected_next_link = string.replace(response.request.url,
                                            "marker=%s" % blocks[1].id,
                                            "marker=%s" % blocks[3].id)

        self.assertEqual(response.status, "200 OK")
        self.assertEqual(len(response_blocks), 2)
        self.assertItemsEqual(response_blocks, _data([blocks[2], blocks[3]]))
        self.assertUrlEqual(expected_next_link, next_link)

    def test_index_with_pagination_for_xml_content_type(self):
        blocks = [factory_models.IpBlockFactory(cidr="10.1.1.0/28"),
                  factory_models.IpBlockFactory(cidr='10.2.1.0/28'),
                  factory_models.IpBlockFactory(cidr='10.3.1.0/28'),
                  factory_models.IpBlockFactory(cidr='10.4.1.0/28'),
                  ]

        blocks = models.sort(blocks)
        response = self.app.get("%s.xml?limit=2&marker=%s"
                                % (self.ip_block_path, blocks[0].id))

        expected_next_link = string.replace(response.request.url,
                                            "marker=%s" % blocks[0].id,
                                            "marker=%s" % blocks[2].id)
        self.assertEqual(response.status, "200 OK")
        self.assertUrlEqual(expected_next_link,
                            response.xml.find("link").attrib["href"])

    def test_index_with_pagination_have_no_next_link_for_last_page(self):
        blocks = [factory_models.IpBlockFactory(cidr="10.1.1.0/28"),
                  factory_models.IpBlockFactory(cidr='10.2.1.0/28'),
                  factory_models.IpBlockFactory(cidr='10.3.1.0/28'),
                  ]

        blocks = models.sort(blocks)

        response = self.app.get("%s?limit=2&marker=%s" % (self.ip_block_path,
                                                          blocks[0].id))

        response_blocks = response.json['ip_blocks']
        self.assertEqual(response.status, "200 OK")
        self.assertEqual(len(response_blocks), 2)
        self.assertTrue("ip_blocks_links" not in response.json)

    def test_create(self):
        req_body = {
            'ip_block': {
                'network_id': "3",
                'cidr': "10.1.1.0/24",
                'type': "public",
                'dns1': "12.34.56.67",
                'dns2': "65.76.87.98",
                },
            }
        response = self.app.post_json("/ipam/tenants/111/ip_blocks.json",
                                      req_body)

        self.assertEqual(response.status, "201 Created")
        saved_block = models.IpBlock.find_by(network_id="3")
        self.assertEqual(saved_block.cidr, "10.1.1.0/24")
        self.assertEqual(saved_block.type, "public")
        self.assertEqual(saved_block.tenant_id, "111")
        self.assertEqual(saved_block.dns1, "12.34.56.67")
        self.assertEqual(saved_block.dns2, "65.76.87.98")
        self.assertEqual(response.json, dict(ip_block=_data(saved_block)))

    def test_create_ignores_tenant_id_passed_in_post_body(self):
        req_body = {
            'ip_block': {
                'network_id': "300",
                'cidr': "10.1.1.0/2",
                'tenant_id': "543",
                'type': "public",
                },
            }

        response = self.app.post_json("/ipam/tenants/111/ip_blocks", req_body)

        saved_block = models.IpBlock.find_by(network_id="300")
        self.assertEqual(saved_block.tenant_id, "111")
        self.assertEqual(response.json, dict(ip_block=_data(saved_block)))

    def test_show_fails_if_block_does_not_belong_to_tenant(self):
        block = factory_models.PrivateIpBlockFactory(tenant_id='0000')
        response = self.app.get("/ipam/tenants/112/ip_blocks/%s" % block.id,
                                status='*')

        self.assertEqual(response.status, "404 Not Found")

    def test_index_scoped_by_tenant(self):
        ip_block1 = factory_models.PrivateIpBlockFactory(cidr="10.0.0.1/8",
                                                         tenant_id='999')
        ip_block2 = factory_models.PrivateIpBlockFactory(cidr="10.0.0.2/8",
                                                         tenant_id='999')
        factory_models.PrivateIpBlockFactory(cidr="10.1.1.1/2",
                                             tenant_id='987')

        response = self.app.get("/ipam/tenants/999/ip_blocks")

        self.assertEqual(response.status, "200 OK")
        response_blocks = response.json['ip_blocks']
        self.assertEqual(len(response_blocks), 2)
        self.assertItemsEqual(response_blocks, _data([ip_block1, ip_block2]))

    def test_update_fails_for_non_existent_block_for_given_tenant(self):
        ip_block = factory_models.PrivateIpBlockFactory(tenant_id="123")
        response = self.app.put_json("/ipam/tenants/321/ip_blocks/%s"
                                     % ip_block.id, {
                                         'ip_block': {'network_id': "foo"},
                                         },
                                     status='*')

        self.assertErrorResponse(response, webob.exc.HTTPNotFound,
                                 "IpBlock Not Found")


class TestSubnetController(BaseTestController):

    def _subnets_path(self, ip_block):
        return "/ipam/tenants/{0}/ip_blocks/{1}/subnets".format(
            ip_block.tenant_id, ip_block.id)

    def test_index(self):
        factory = factory_models.IpBlockFactory
        parent = factory(cidr="10.0.0.0/28")
        subnet1 = factory(cidr="10.0.0.0/29", parent_id=parent.id)
        subnet2 = factory(cidr="10.0.0.8/29", parent_id=parent.id)

        response = self.app.get(self._subnets_path(parent))

        self.assertEqual(response.status_int, 200)
        self.assertItemsEqual(response.json['subnets'],
                              _data([subnet1, subnet2]))

    def test_create(self):
        parent = factory_models.IpBlockFactory(cidr="10.0.0.0/28",
                                               tenant_id="123")

        response = self.app.post_json(self._subnets_path(parent),
                                 {'subnet': {
                                          'cidr': "10.0.0.0/29",
                                          'network_id': "2",
                                          'tenant_id': "321",
                                          },
                                  })

        subnet = models.IpBlock.find_by(parent_id=parent.id)
        self.assertEqual(response.status_int, 201)
        self.assertEqual(subnet.network_id, "2")
        self.assertEqual(subnet.cidr, "10.0.0.0/29")
        self.assertEqual(subnet.tenant_id, "321")
        self.assertEqual(response.json['subnet'], _data(subnet))

    def test_create_excludes_uneditable_fields(self):
        parent = factory_models.IpBlockFactory(cidr="10.0.0.0/28")

        response = self.app.post_json(self._subnets_path(parent),
                                 {'subnet': {
                                          'cidr': "10.0.0.0/29",
                                          'type': "Input type",
                                          'parent_id': "Input parent",
                                          },
                                  })

        subnet = models.IpBlock.find_by(parent_id=parent.id)
        self.assertEqual(response.status_int, 201)
        self.assertNotEqual(subnet.type, "Input type")
        self.assertNotEqual(subnet.parent_id, "Input parent")


class TestIpAddressController(BaseTestController):

    def _address_path(self, block):
        return ("/ipam/tenants/{0}/ip_blocks/{1}/"
                "ip_addresses".format(block.tenant_id, block.id))

    def test_create(self):
        block = factory_models.IpBlockFactory(cidr="10.1.1.0/28")
        response = self.app.post(self._address_path(block))

        self.assertEqual(response.status, "201 Created")
        allocated_address = models.IpAddress.find_by(ip_block_id=block.id)
        self.assertEqual(allocated_address.address, "10.1.1.0")
        self.assertEqual(response.json,
                         dict(ip_address=_data(allocated_address)))

    def test_create_with_given_address(self):
        block = factory_models.IpBlockFactory(cidr="10.1.1.0/28")
        response = self.app.post_json(self._address_path(block),
                                      {'ip_address': {"address": '10.1.1.2'}})

        self.assertEqual(response.status, "201 Created")
        created_address_id = response.json['ip_address']['id']
        created_ip = models.IpAddress.find(created_address_id)
        self.assertEqual(created_ip.address, "10.1.1.2"),

    def test_create_with_interface(self):
        block = factory_models.IpBlockFactory()

        self.app.post_json(self._address_path(block),
                           {'ip_address': {"interface_id": "1111"}})

        allocated_address = models.IpAddress.find_by(ip_block_id=block.id)
        self.assertEqual(allocated_address.interface_id, "1111")

    def test_create_given_the_tenant_using_the_ip(self):
        block = factory_models.IpBlockFactory()

        self.app.post_json(self._address_path(block),
                           {'ip_address': {"tenant_id": "RAX"}})

        allocated_address = models.IpAddress.find_by(ip_block_id=block.id)
        self.assertEqual(allocated_address.used_by_tenant, "RAX")

    def test_create_given_the_device_using_the_ip(self):
        block = factory_models.IpBlockFactory()

        self.app.post_json(self._address_path(block),
                           {'ip_address': {"used_by_device": "instance_id"}})

        allocated_address = models.IpAddress.find_by(ip_block_id=block.id)
        self.assertEqual(allocated_address.used_by_device, "instance_id")

    def test_create_ipv6_address_fails_when_mac_address_not_given(self):
        block = factory_models.IpBlockFactory(cidr="ff::/64")

        response = self.app.post_json(self._address_path(block),
                                      {'ip_address': {"interface_id": "1111"}},
                                      status="*")

        self.assertErrorResponse(response, webob.exc.HTTPBadRequest,
                                 "Required params are missing: mac_address")

    def test_create_passes_request_params_to_ipv6_allocation_algorithm(self):
        block = factory_models.IpBlockFactory(cidr="ff::/64")
        params = {'ip_address': {"interface_id": "123",
                                 'mac_address': "10:23:56:78:90:01",
                                 'tenant_id': "111",
                                 },
                  }
        generated_ip = factory_models.IpAddressFactory(address="ff::1",
                                                       ip_block_id=block.id)
        self.mock.StubOutWithMock(models.IpBlock, "allocate_ip")
        models.IpBlock.allocate_ip(interface_id="123",
                                   mac_address="10:23:56:78:90:01",
                                   used_by_tenant="111"
                                   ).AndReturn(generated_ip)

        self.mock.ReplayAll()
        response = self.app.post_json(self._address_path(block), params)

        self.assertEqual(response.status_int, 201)

    def test_show(self):
        block = factory_models.IpBlockFactory(cidr='10.1.1.1/30')
        ip = block.allocate_ip(interface_id="3333")

        response = self.app.get("{0}/{1}.json".format(
            self._address_path(block), ip.address))

        self.assertEqual(response.status, "200 OK")
        self.assertEqual(response.json, dict(ip_address=_data(ip)))

    def test_show_fails_for_nonexistent_address(self):
        block = factory_models.IpBlockFactory(cidr="10.1.1.0/28")

        response = self.app.get("{0}/{1}".format(self._address_path(block),
                                                 '10.1.1.0'),
                                status="*")

        self.assertEqual(response.status, "404 Not Found")
        self.assertTrue("IpAddress Not Found" in response.body)

    def test_delete_ip(self):
        block = factory_models.IpBlockFactory(cidr='10.1.1.1/30')
        ip = block.allocate_ip()

        response = self.app.delete("{0}/{1}.xml".format(
            self._address_path(block), ip.address))

        self.assertEqual(response.status, "200 OK")
        self.assertIsNotNone(models.IpAddress.find(ip.id))
        self.assertTrue(models.IpAddress.find(ip.id).marked_for_deallocation)

    def test_index(self):
        block = factory_models.IpBlockFactory()
        address1, address2 = models.sort([block.allocate_ip()
                                            for i in range(2)])

        response = self.app.get(self._address_path(block))

        ip_addresses = response.json["ip_addresses"]
        self.assertEqual(response.status, "200 OK")
        self.assertEqual(len(ip_addresses), 2)
        self.assertEqual(ip_addresses[0]['address'], address1.address)
        self.assertEqual(ip_addresses[1]['address'], address2.address)

    def test_index_with_pagination(self):
        block = factory_models.IpBlockFactory()
        ips = models.sort([block.allocate_ip() for i in range(5)])

        response = self.app.get("{0}?limit=2&marker={1}".format(
                self._address_path(block), ips[1].id))

        ip_addresses = response.json["ip_addresses"]
        next_link = response.json["ip_addresses_links"][0]['href']
        expected_next_link = string.replace(response.request.url,
                                            "marker=%s" % ips[1].id,
                                            "marker=%s" % ips[3].id)

        self.assertEqual(len(ip_addresses), 2)
        self.assertEqual(ip_addresses[0]['address'], ips[2].address)
        self.assertEqual(ip_addresses[1]['address'], ips[3].address)
        self.assertUrlEqual(expected_next_link, next_link)

    def test_restore_deallocated_ip(self):
        block = factory_models.IpBlockFactory()
        ips = [block.allocate_ip() for i in range(5)]
        block.deallocate_ip(ips[0].address)

        response = self.app.put_json("{0}/{1}/restore".format(
                self._address_path(block), ips[0].address), {})

        ip_addresses = [ip.address for ip in
                        models.IpAddress.find_all(ip_block_id=block.id)]
        self.assertEqual(response.status, "200 OK")
        self.assertItemsEqual(ip_addresses, [ip.address for ip in ips])

    def test_show_fails_for_non_existent_block_for_given_tenant(self):
        block = factory_models.IpBlockFactory(tenant_id=123)
        ip_address = factory_models.IpAddressFactory(ip_block_id=block.id)
        self.block_path = "/ipam/tenants/111/ip_blocks"
        response = self.app.get("%s/%s/ip_addresses/%s"
                                 % (self.block_path,
                                    block.id,
                                    ip_address.address),
                                status='*')

        self.assertErrorResponse(response, webob.exc.HTTPNotFound,
                                 "IpBlock Not Found")

    def test_index_fails_for_non_existent_block_for_given_tenant(self):
        block = factory_models.IpBlockFactory(tenant_id="123")

        self.block_path = "/ipam/tenants/111/ip_blocks"
        response = self.app.get("%s/%s/ip_addresses"
                                 % (self.block_path, block.id),
                                 status='*')

        self.assertErrorResponse(response, webob.exc.HTTPNotFound,
                                 "IpBlock Not Found")

    def test_restore_fails_for_non_existent_block_for_given_tenant(self):
        block = factory_models.IpBlockFactory(tenant_id=123)
        ip_address = factory_models.IpAddressFactory(ip_block_id=block.id)
        block.deallocate_ip(ip_address.address)
        self.block_path = "/ipam/tenants/111/ip_blocks"
        response = self.app.put_json("%s/%s/ip_addresses/%s/restore"
                                 % (self.block_path, block.id,
                                    ip_address.address), {},
                                 status='*')

        self.assertErrorResponse(response, webob.exc.HTTPNotFound,
                                 "IpBlock Not Found")

    def test_create_fails_for_non_existent_block_for_given_tenant(self):
        block = factory_models.IpBlockFactory(tenant_id=123)
        self.block_path = "/ipam/tenants/111/ip_blocks"
        response = self.app.post("%s/%s/ip_addresses"
                                 % (self.block_path, block.id),
                                 status='*')

        self.assertErrorResponse(response, webob.exc.HTTPNotFound,
                                 "IpBlock Not Found")

    def test_delete_fails_for_non_existent_block_for_given_tenant(self):
        block = factory_models.IpBlockFactory(tenant_id=123)
        ip_address = factory_models.IpAddressFactory(ip_block_id=block.id)
        self.block_path = "/ipam/tenants/111/ip_blocks"
        response = self.app.delete("%s/%s/ip_addresses/%s"
                                 % (self.block_path, block.id,
                                    ip_address.address),
                                 status='*')

        self.assertErrorResponse(response, webob.exc.HTTPNotFound,
                                 "IpBlock Not Found")


class TestAllocatedIpAddressController(BaseTestController):

    def test_index_returns_allocated_ips_as_paginated_set(self):
        ip_block1 = factory_models.IpBlockFactory(cidr="10.0.0.0/24")
        ip_block2 = factory_models.IpBlockFactory(cidr="20.0.0.0/24")

        block1_ips, block2_ips = _allocate_ips((ip_block1, 3), (ip_block2, 4))

        allocated_ips = models.sort(block1_ips + block2_ips)
        response = self.app.get("/ipam/allocated_ip_addresses?"
                                "limit=4&marker=%s" % allocated_ips[1].id)
        self.assertEqual(response.status_int, 200)
        self.assertEqual(len(response.json['ip_addresses']), 4)
        self.assertEqual(response.json['ip_addresses'],
                         _data(allocated_ips[2:6]))

    def test_index_returns_allocated_ips_for_tenant(self):
        tenant1_block1 = factory_models.IpBlockFactory(cidr="10.0.0.0/24",
                                                       tenant_id="1")
        block2 = factory_models.IpBlockFactory(cidr="20.0.0.0/24",
                                               tenant_id="2")
        tenant1_ip1 = tenant1_block1.allocate_ip()
        tenant1_ip2 = block2.allocate_ip(used_by_tenant="1")
        tenant2_ip1 = block2.allocate_ip()

        response = self.app.get("/ipam/tenants/1/allocated_ip_addresses")

        self.assertItemsEqual(response.json['ip_addresses'],
                              _data([tenant1_ip1, tenant1_ip2]))

    def test_index_returns_allocated_ips_by_device(self):
        block1 = factory_models.IpBlockFactory(cidr="10.0.0.0/24",
                                               tenant_id="1")
        block2 = factory_models.IpBlockFactory(cidr="20.0.0.0/24",
                                               tenant_id="2")

        instance1_ip1 = block1.allocate_ip(used_by_device="1")
        instance1_ip2 = block2.allocate_ip(used_by_device="1")
        instance2_ip1 = block2.allocate_ip(used_by_device="2")

        response = self.app.get("/ipam/allocated_ip_addresses?"
                                "used_by_device=1")

        self.assertItemsEqual(response.json['ip_addresses'],
                              _data([instance1_ip1, instance1_ip2]))

    def test_index_returns_allocated_ips_by_device_for_tenant(self):
        block1 = factory_models.IpBlockFactory(cidr="10.0.0.0/24",
                                               tenant_id="1")
        block2 = factory_models.IpBlockFactory(cidr="20.0.0.0/24",
                                               tenant_id="2")

        tnt1_device1_ip1 = block1.allocate_ip(used_by_device="1")
        tnt1_device1_ip2 = block2.allocate_ip(used_by_device="1",
                                              used_by_tenant="1")
        tnt1_device2_ip1 = block1.allocate_ip(used_by_device="2")
        tnt2_device1_ip1 = block2.allocate_ip(used_by_device="1")

        response = self.app.get("/ipam/tenants/1/allocated_ip_addresses?"
                                "used_by_device=1")

        self.assertItemsEqual(response.json['ip_addresses'],
                              _data([tnt1_device1_ip1, tnt1_device1_ip2]))

    def test_index_doesnt_return_soft_deallocated_ips(self):
        block = factory_models.IpBlockFactory(tenant_id="1")

        ip1 = block.allocate_ip()
        ip2 = block.allocate_ip()
        ip3 = block.allocate_ip()

        ip2.deallocate()
        response = self.app.get("/ipam/tenants/1/allocated_ip_addresses")

        self.assertItemsEqual(response.json['ip_addresses'], _data([ip1, ip3]))


class TestInsideGlobalsController(BaseTestController):

    def _nat_path(self, block, address):
        return ("/ipam/tenants/{0}/ip_blocks/{1}/ip_addresses/{2}"
                "/inside_globals".format(block.tenant_id,
                                         block.id,
                                         address))

    def test_index(self):
        local_block = factory_models.PrivateIpBlockFactory(cidr="10.1.1.1/30")
        public_factory = factory_models.PublicIpBlockFactory
        global_block1 = public_factory(cidr="192.1.1.1/30")
        global_block2 = public_factory(cidr="196.1.1.1/30")

        local_ip = local_block.allocate_ip()
        global_ip1 = global_block1.allocate_ip()
        global_ip2 = global_block2.allocate_ip()

        local_ip.add_inside_globals([global_ip1, global_ip2])

        response = self.app.get(self._nat_path(local_block, local_ip.address))

        self.assertItemsEqual(response.json['ip_addresses'],
                              _data([global_ip1, global_ip2]))

    def test_index_with_pagination(self):
        local_block = factory_models.PrivateIpBlockFactory(cidr="10.1.1.1/8")
        global_block = factory_models.PublicIpBlockFactory(cidr="192.1.1.1/8")

        [local_ip], global_ips = _allocate_ips((local_block, 1),
                                               (global_block, 5))
        local_ip.add_inside_globals(global_ips)

        response = self.app.get("{0}?limit=2&marker={1}".
                                format(self._nat_path(local_block,
                                                      local_ip.address),
                                       global_ips[1].id))

        self.assertEqual(response.json['ip_addresses'],
                         _data([global_ips[2], global_ips[3]]))

    def test_index_for_nonexistent_block(self):
        non_existant_block_id = 12122
        url = "/ipam/tenants/tnt/ip_blocks/%s/ip_addresses/%s/inside_globals"
        response = self.app.get(url % (non_existant_block_id, "10.1.1.2"),
                                status='*')

        self.assertErrorResponse(response, webob.exc.HTTPNotFound,
                                 "IpBlock Not Found")

    def test_index_for_nonexistent_block_for_given_tenant(self):
        block = factory_models.PrivateIpBlockFactory(cidr="10.0.0.0/24",
                                                     tenant_id="tnt_id")

        url = ("/ipam/tenants/bad_tenant_id/ip_blocks/%s"
               "/ip_addresses/%s/inside_globals")
        response = self.app.get(url % (block.id, "10.1.1.2"), status='*')

        self.assertErrorResponse(response, webob.exc.HTTPNotFound,
                                 "IpBlock Not Found")

    def test_index_for_nonexistent_address(self):
        ip_block = factory_models.PrivateIpBlockFactory(cidr="191.1.1.1/10")
        response = self.app.get(self._nat_path(ip_block, '10.1.1.2'),
                                status='*')

        self.assertErrorResponse(response, webob.exc.HTTPNotFound,
                                 "IpAddress Not Found")

    def test_create(self):
        local_block = factory_models.PrivateIpBlockFactory(cidr="10.1.1.1/24")
        global_block = factory_models.PublicIpBlockFactory(cidr="77.1.1.1/24")

        global_ip = global_block.allocate_ip()
        local_ip = local_block.allocate_ip()
        response = self.app.post_json(self._nat_path(local_block,
                                                     local_ip.address),
                                      {'ip_addresses': [{
                                          'ip_block_id': global_block.id,
                                          'ip_address': global_ip.address
                                          }]
                                       })

        self.assertEqual(response.status, "200 OK")

        self.assertEqual(len(local_ip.inside_globals()), 1)
        self.assertEqual(global_ip.id, local_ip.inside_globals()[0].id)
        self.assertEqual(local_ip.id, global_ip.inside_locals()[0].id)

    def test_create_throws_error_for_ips_of_other_tenants_blocks(self):
        local_block = factory_models.PublicIpBlockFactory(cidr="77.1.1.0/28")
        other_tenant_global_block = factory_models.PrivateIpBlockFactory(
            cidr="10.1.1.0/28", tenant_id="other_tenant_id")

        json_data = [{
            'ip_block_id': other_tenant_global_block.id,
             'ip_address': "10.1.1.2",
            }]
        request_data = {'ip_addresses': json_data}

        response = self.app.post_json(self._nat_path(local_block, "77.1.1.0"),
                                      request_data, status="*")

        self.assertEqual(response.status_int, 404)
        self.assertErrorResponse(response, webob.exc.HTTPNotFound,
                                 "IpBlock Not Found")

    def test_create_for_nonexistent_block(self):
        non_existant_block_id = 1234

        url = "/ipam/tenants/tnt/ip_blocks/%s/ip_addresses/%s/inside_globals"
        response = self.app.post_json(url % (non_existant_block_id,
                                             "10.1.1.2"),
                                      {'ip_addresses': [{
                                          'ip_block_id': "5678",
                                          'ip_address': "10.0.0.0",
                                          }]
                                       },
                                      status='*')

        self.assertErrorResponse(response, webob.exc.HTTPNotFound,
                                 "IpBlock Not Found")

    def test_create_for_nonexistent_block_for_given_tenant(self):
        block = factory_models.PrivateIpBlockFactory(cidr="10.0.0.0/24",
                                                     tenant_id="tnt_id")

        url = ("/ipam/tenants/bad_tenant_id/ip_blocks/%s"
               "/ip_addresses/%s/inside_globals")
        response = self.app.post_json(url % (block.id, "10.1.1.2"),
                                      {'ip_addresses': [{
                                          'ip_block_id': "5678",
                                          'ip_address': "10.0.0.0",
                                          }]
                                       },
                                      status='*')

        self.assertErrorResponse(response, webob.exc.HTTPNotFound,
                                 "IpBlock Not Found")

    def test_delete(self):
        local_block = factory_models.PrivateIpBlockFactory(cidr="10.1.1.1/24")
        global_block = factory_models.PublicIpBlockFactory(cidr="77.1.1.1/24")

        global_ip = global_block.allocate_ip()
        local_ip = local_block.allocate_ip()
        local_ip.add_inside_globals([global_ip])

        response = self.app.delete(self._nat_path(local_block,
                                                  local_ip.address))

        self.assertEqual(response.status, "200 OK")
        self.assertEqual(local_ip.inside_globals(), [])

    def test_delete_for_specific_address(self):
        local_block = factory_models.PrivateIpBlockFactory(cidr="10.1.1.1/8")
        global_block = factory_models.PublicIpBlockFactory(cidr="192.1.1.1/8")

        global_ips, = _allocate_ips((global_block, 3))
        local_ip = local_block.allocate_ip()
        local_ip.add_inside_globals(global_ips)

        self.app.delete("%s/%s" % (self._nat_path(local_block,
                                                  local_ip.address),
                                   global_ips[1].address))

        globals_left = [ip.address for ip in local_ip.inside_globals()]
        self.assertEqual(globals_left, [global_ips[0].address,
                                        global_ips[2].address])

    def test_delete_for_nonexistent_block(self):
        non_existant_block_id = 12122
        url = "/ipam/tenants/tnt/ip_blocks/%s/ip_addresses/%s/inside_globals"
        response = self.app.delete(url % (non_existant_block_id, '10.1.1.2'),
                                   status='*')

        self.assertErrorResponse(response, webob.exc.HTTPNotFound,
                                 "IpBlock Not Found")

    def test_delete_for_nonexistent_block_for_given_tenant(self):
        block = factory_models.PrivateIpBlockFactory(cidr="10.0.0.0/24",
                                                     tenant_id="tnt_id")

        url = ("/ipam/tenants/bad_tenant_id/ip_blocks/%s"
               "/ip_addresses/%s/inside_globals")
        response = self.app.delete(url % (block.id, "10.1.1.2"), status='*')

        self.assertErrorResponse(response, webob.exc.HTTPNotFound,
                                 "IpBlock Not Found")

    def test_delete_for_nonexistent_address(self):
        ip_block = factory_models.PrivateIpBlockFactory(cidr="191.1.1.1/10")
        response = self.app.delete(self._nat_path(ip_block, '10.1.1.2'),
                                   status='*')

        self.assertErrorResponse(response, webob.exc.HTTPNotFound,
                                 "IpAddress Not Found")


class TestInsideLocalsController(BaseTestController):

    def _nat_path(self, block, address):
        return ("/ipam/tenants/{0}/ip_blocks/{1}/ip_addresses/{2}"
                "/inside_locals".format(block.tenant_id,
                                         block.id,
                                         address))

    def test_index(self):
        local_block = factory_models.PrivateIpBlockFactory(cidr="10.1.1.1/24")
        global_block = factory_models.PublicIpBlockFactory(cidr="77.1.1.1/24")

        [global_ip], local_ips = _allocate_ips((global_block, 1),
                                               (local_block, 5))
        global_ip.add_inside_locals(local_ips)

        response = self.app.get(self._nat_path(global_block,
                                               global_ip.address))

        self.assertEqual(response.json['ip_addresses'], _data(local_ips))

    def test_index_with_pagination(self):
        local_block = factory_models.PrivateIpBlockFactory(cidr="10.1.1.1/24")
        global_block = factory_models.PublicIpBlockFactory(cidr="77.1.1.1/24")

        [global_ip], local_ips = _allocate_ips((global_block, 1),
                                               (local_block, 5))
        global_ip.add_inside_locals(local_ips)

        response = self.app.get("{0}?limit=2&marker={1}".
                                format(self._nat_path(global_block,
                                                      global_ip.address),
                                       local_ips[1].id))

        self.assertEqual(response.json['ip_addresses'],
                         _data([local_ips[2], local_ips[3]]))

    def test_index_for_nonexistent_block(self):
        non_existant_block_id = 12122
        url = "/ipam/tenants/tnt/ip_blocks/%s/ip_addresses/%s/inside_locals"
        response = self.app.get(url % (non_existant_block_id, "10.1.1.2"),
                                status='*')

        self.assertErrorResponse(response, webob.exc.HTTPNotFound,
                                 "IpBlock Not Found")

    def test_index_for_nonexistent_block_for_given_tenant(self):
        block = factory_models.PrivateIpBlockFactory(cidr="10.0.0.0/24",
                                                     tenant_id="tnt_id")

        url = ("/ipam/tenants/bad_tenant_id/ip_blocks/%s"
               "/ip_addresses/%s/inside_locals")
        response = self.app.get(url % (block.id, "10.1.1.2"), status='*')

        self.assertErrorResponse(response, webob.exc.HTTPNotFound,
                                 "IpBlock Not Found")

    def test_index_for_nonexistent_address(self):
        ip_block = factory_models.PrivateIpBlockFactory(cidr="191.1.1.1/10")
        response = self.app.get(self._nat_path(ip_block, '10.1.1.2'),
                                status='*')

        self.assertErrorResponse(response, webob.exc.HTTPNotFound,
                                 "IpAddress Not Found")

    def test_create(self):
        global_block = factory_models.PublicIpBlockFactory(cidr="77.1.1.0/28")
        local_block1 = factory_models.PrivateIpBlockFactory(cidr="10.1.1.0/28")
        local_block2 = factory_models.PrivateIpBlockFactory(cidr="10.0.0.0/28")

        json_data = [
            {'ip_block_id': local_block1.id, 'ip_address': "10.1.1.2"},
            {'ip_block_id': local_block2.id, 'ip_address': "10.0.0.2"},
        ]
        request_data = {'ip_addresses': json_data}
        response = self.app.post_json(self._nat_path(global_block, "77.1.1.0"),
                                      request_data)

        self.assertEqual(response.status, "200 OK")
        ips = global_block.find_allocated_ip("77.1.1.0").inside_locals()
        inside_locals = [ip.address for ip in ips]

        self.assertEqual(len(inside_locals), 2)
        self.assertTrue("10.1.1.2" in inside_locals)
        self.assertTrue("10.0.0.2" in inside_locals)
        local_ip = models.IpAddress.find_by(ip_block_id=local_block1.id,
                                            address="10.1.1.2")
        self.assertEqual(local_ip.inside_globals()[0].address, "77.1.1.0")

    def test_create_throws_error_for_ips_of_other_tenants_blocks(self):
        global_block = factory_models.PublicIpBlockFactory(cidr="77.1.1.0/28")
        other_tenant_local_block = factory_models.PrivateIpBlockFactory(
            cidr="10.1.1.0/28", tenant_id="other_tenant_id")

        json_data = [{
            'ip_block_id': other_tenant_local_block.id,
             'ip_address': "10.1.1.2",
            }]
        request_data = {'ip_addresses': json_data}

        response = self.app.post_json(self._nat_path(global_block, "77.1.1.0"),
                                      request_data, status="*")

        self.assertEqual(response.status_int, 404)
        self.assertErrorResponse(response, webob.exc.HTTPNotFound,
                                 "IpBlock Not Found")

    def test_create_for_nonexistent_block_for_given_tenant(self):
        block = factory_models.PrivateIpBlockFactory(cidr="10.0.0.0/24",
                                                     tenant_id="tnt_id")

        url = ("/ipam/tenants/bad_tenant_id/ip_blocks/%s"
               "/ip_addresses/%s/inside_locals")
        response = self.app.post_json(url % (block.id, "10.1.1.2"),
                                      {'ip_addresses': [{
                                          'ip_block_id': "5678",
                                          'ip_address': "10.0.0.0",
                                          }]
                                       },
                                      status='*')

        self.assertErrorResponse(response, webob.exc.HTTPNotFound,
                                 "IpBlock Not Found")

    def test_delete_for_specific_address(self):
        local_block = factory_models.PrivateIpBlockFactory(cidr="10.1.1.1/24")
        global_block = factory_models.PublicIpBlockFactory(cidr="77.1.1.1/24")

        local_ips, = _allocate_ips((local_block, 3))
        global_ip = global_block.allocate_ip()
        global_ip.add_inside_locals(local_ips)

        self.app.delete("{0}/{1}".format(self._nat_path(global_block,
                                                        global_ip.address),
                                         local_ips[1].address))

        locals_left = [ip.address for ip in global_ip.inside_locals()]
        self.assertEqual(locals_left,
                         [local_ips[0].address, local_ips[2].address])

    def test_delete(self):
        local_block = factory_models.PrivateIpBlockFactory(cidr="10.1.1.1/24")
        global_block = factory_models.PublicIpBlockFactory(cidr="77.1.1.1/24")

        global_ip = global_block.allocate_ip()
        local_ip = local_block.allocate_ip()
        global_ip.add_inside_locals([local_ip])

        response = self.app.delete(self._nat_path(global_block,
                                                  global_ip.address))

        self.assertEqual(response.status, "200 OK")
        self.assertEqual(global_ip.inside_locals(), [])

    def test_delete_for_nonexistent_block(self):
        non_existant_block_id = 12122
        url = "/ipam/tenants/tnt/ip_blocks/%s/ip_addresses/%s/inside_locals"
        response = self.app.delete(url % (non_existant_block_id, '10.1.1.2'),
                                   status='*')

        self.assertErrorResponse(response, webob.exc.HTTPNotFound,
                                 "IpBlock Not Found")

    def test_delete_for_nonexistent_block_for_given_tenant(self):
        block = factory_models.PrivateIpBlockFactory(cidr="10.0.0.0/24",
                                                     tenant_id="tnt_id")

        url = ("/ipam/tenants/bad_tenant_id/ip_blocks/%s"
               "/ip_addresses/%s/inside_locals")
        response = self.app.delete(url % (block.id, "10.1.1.2"), status='*')

        self.assertErrorResponse(response, webob.exc.HTTPNotFound,
                                 "IpBlock Not Found")

    def test_delete_for_nonexistent_address(self):
        ip_block = factory_models.PrivateIpBlockFactory(cidr="191.1.1.1/10")
        response = self.app.delete(self._nat_path(ip_block, '10.1.1.2'),
                                   status='*')

        self.assertErrorResponse(response, webob.exc.HTTPNotFound,
                                 "IpAddress Not Found")


class TestUnusableIpRangesController(BaseTestController):

    def setUp(self):
        self.policy_path = "/ipam/tenants/tnt_id/policies"
        super(TestUnusableIpRangesController, self).setUp()

    def test_create(self):
        policy = factory_models.PolicyFactory(tenant_id="tnt_id")

        response = self.app.post_json("%s/%s/unusable_ip_ranges"
                                      % (self.policy_path, policy.id),
                                      {'ip_range': {
                                          'offset': '10',
                                          'length': '2',
                                          },
                                       })

        unusable_range = models.IpRange.find_by(policy_id=policy.id)
        self.assertEqual(response.status, "201 Created")
        self.assertEqual(response.json, dict(ip_range=_data(unusable_range)))

    def test_create_on_non_existent_policy(self):
        response = self.app.post_json("%s/bad_policy_id/unusable_ip_ranges"
                                      % self.policy_path,
                                      {'ip_range': {
                                          'offset': '1',
                                          'length': '2',
                                          },
                                       },
                                      status="*")

        self.assertErrorResponse(response, webob.exc.HTTPNotFound,
                                 "Policy Not Found")

    def test_create_fails_for_non_existent_policy_for_given_tenant(self):
        policy = factory_models.PolicyFactory(tenant_id=123)
        self.policy_path = "/ipam/tenants/another_tenant_id/policies"
        response = self.app.post_json("%s/%s/unusable_ip_ranges"
                                      % (self.policy_path, policy.id),
                                      {'ip_range': {
                                          'offset': 1,
                                          'length': 20,
                                          },
                                       },
                                      status='*')

        self.assertErrorResponse(response, webob.exc.HTTPNotFound,
                                 "Policy Not Found")

    def test_show(self):
        policy = factory_models.PolicyFactory(tenant_id="tnt_id")
        ip_range = factory_models.IpRangeFactory.create(policy_id=policy.id)

        response = self.app.get("%s/%s/unusable_ip_ranges/%s"
                                % (self.policy_path, policy.id, ip_range.id))

        self.assertEqual(response.status_int, 200)
        self.assertEqual(response.json, dict(ip_range=_data(ip_range)))

    def test_show_when_ip_range_does_not_exists(self):
        policy = factory_models.PolicyFactory(tenant_id="tnt_id")

        response = self.app.get("%s/%s/unusable_ip_ranges/bad_ip_range_id"
                                % (self.policy_path, policy.id),
                                status="*")

        self.assertErrorResponse(response, webob.exc.HTTPNotFound,
                                 "IpRange Not Found")

    def test_show_fails_for_non_existent_policy_for_given_tenant(self):
        policy = factory_models.PolicyFactory(tenant_id="123")
        ip_range = factory_models.IpRangeFactory(policy_id=policy.id)
        self.policy_path = "/ipam/tenants/bad_tenant_id/policies"
        response = self.app.get("%s/%s/unusable_ip_ranges/%s"
                                % (self.policy_path, policy.id, ip_range.id),
                                status='*')

        self.assertErrorResponse(response, webob.exc.HTTPNotFound,
                                 "Policy Not Found")

    def test_update(self):
        policy = factory_models.PolicyFactory(tenant_id="tnt_id")
        ip_range = factory_models.IpRangeFactory.create(offset=10,
                                                        length=11,
                                                        policy_id=policy.id)

        response = self.app.put_json("%s/%s/unusable_ip_ranges/%s"
                                     % (self.policy_path,
                                        policy.id,
                                        ip_range.id),
                                     {'ip_range': {
                                         'offset': 1111,
                                         'length': 2222,
                                         },
                                      })

        self.assertEqual(response.status_int, 200)
        updated_range = models.IpRange.find(ip_range.id)
        self.assertEqual(updated_range.offset, 1111)
        self.assertEqual(updated_range.length, 2222)
        self.assertEqual(response.json, dict(ip_range=_data(updated_range)))

    def test_update_ignores_change_in_policy_id(self):
        policy = factory_models.PolicyFactory(tenant_id="tnt_id")
        ip_range = factory_models.IpRangeFactory.create(offset=10,
                                                        length=11,
                                                        policy_id=policy.id)
        new_policy_id = utils.generate_uuid()
        response = self.app.put_json("%s/%s/unusable_ip_ranges/%s"
                                     % (self.policy_path,
                                        policy.id,
                                        ip_range.id),
                                     {'ip_range': {
                                         'offset': 1111,
                                         'length': 2222,
                                         'policy_id': new_policy_id,
                                         },
                                      })

        self.assertEqual(response.status_int, 200)
        updated_range = models.IpRange.find(ip_range.id)
        self.assertEqual(updated_range.offset, 1111)
        self.assertEqual(updated_range.policy_id, policy.id)
        self.assertEqual(response.json['ip_range']['policy_id'], policy.id)

    def test_update_when_ip_range_does_not_exists(self):
        policy = factory_models.PolicyFactory(tenant_id="tnt_id")

        response = self.app.put_json("%s/%s/unusable_ip_ranges/bad_ip_range_id"
                                     % (self.policy_path, policy.id),
                                     {'ip_range': {
                                         'offset': 1111,
                                         'length': 222,
                                         },
                                      },
                                     status="*")

        self.assertErrorResponse(response, webob.exc.HTTPNotFound,
                                 "IpRange Not Found")

    def test_update_fails_for_non_existent_policy_for_given_tenant(self):
        policy = factory_models.PolicyFactory(tenant_id=123)
        ip_range = factory_models.IpRangeFactory(policy_id=policy.id)
        self.policy_path = "/ipam/tenants/another_tenant_id/policies"
        response = self.app.put_json("%s/%s/unusable_ip_ranges/%s"
                                     % (self.policy_path,
                                        policy.id,
                                        ip_range.id),
                                     {'ip_range': {'offset': 1}}, status='*')

        self.assertErrorResponse(response, webob.exc.HTTPNotFound,
                                 "Policy Not Found")

    def test_index(self):
        policy = factory_models.PolicyFactory(tenant_id="tnt_id")
        for i in range(0, 3):
            factory_models.IpRangeFactory(policy_id=policy.id)

        response = self.app.get("%s/%s/unusable_ip_ranges"
                                % (self.policy_path, policy.id))

        response_ranges = response.json["ip_ranges"]
        self.assertEqual(len(response_ranges), 3)
        self.assertItemsEqual(response_ranges,
                              _data(policy.unusable_ip_ranges))

    def test_index_with_pagination(self):
        policy = factory_models.PolicyFactory(tenant_id="tnt_id")
        ip_ranges = [factory_models.IpRangeFactory(policy_id=policy.id)
                     for i in range(0, 5)]
        ip_ranges = models.sort(ip_ranges)

        response = self.app.get("%s/%s/unusable_ip_ranges?limit=2&marker=%s"
                                % (self.policy_path,
                                   policy.id,
                                   ip_ranges[0].id))

        next_link = response.json["ip_ranges_links"][0]['href']
        expected_next_link = string.replace(response.request.url,
                                            "marker=%s" % ip_ranges[0].id,
                                            "marker=%s" % ip_ranges[2].id)

        response_ranges = response.json["ip_ranges"]
        self.assertEqual(len(response_ranges), 2)
        self.assertItemsEqual(response_ranges, _data(ip_ranges[1:3]))
        self.assertUrlEqual(next_link, expected_next_link)

    def test_index_fails_for_non_existent_policy_for_given_tenant(self):
        policy = factory_models.PolicyFactory(tenant_id=123)
        self.policy_path = "/ipam/tenants/another_tenant_id/policies"
        response = self.app.get("%s/%s/unusable_ip_ranges"
                                % (self.policy_path, policy.id),
                                status='*')

        self.assertErrorResponse(response, webob.exc.HTTPNotFound,
                                 "Policy Not Found")

    def test_delete(self):
        policy = factory_models.PolicyFactory(tenant_id="tnt_id")
        ip_range = factory_models.IpRangeFactory(policy_id=policy.id)

        response = self.app.delete("%s/%s/unusable_ip_ranges/%s"
                                   % (self.policy_path,
                                      policy.id,
                                      ip_range.id))

        self.assertEqual(response.status_int, 200)
        self.assertRaises(models.ModelNotFoundError,
                          policy.find_ip_range,
                          ip_range_id=ip_range.id)

    def test_delete_fails_for_non_existent_policy_for_given_tenant(self):
        policy = factory_models.PolicyFactory(tenant_id=123)
        ip_range = factory_models.IpRangeFactory(policy_id=policy.id)
        self.policy_path = "/ipam/tenants/another_tenant_id/policies"
        response = self.app.delete("%s/%s/unusable_ip_ranges/%s"
                                   % (self.policy_path,
                                      policy.id,
                                      ip_range.id),
                                   status='*')

        self.assertErrorResponse(response, webob.exc.HTTPNotFound,
                                 "Policy Not Found")


class TestUnusableIpOctetsController(BaseTestController):

    def setUp(self):
        self.policy_path = "/ipam/tenants/tnt_id/policies"
        super(TestUnusableIpOctetsController, self).setUp()

    def test_index(self):
        policy = factory_models.PolicyFactory(tenant_id="tnt_id")
        for i in range(0, 3):
            factory_models.IpOctetFactory(policy_id=policy.id)

        response = self.app.get("%s/%s/unusable_ip_octets" % (self.policy_path,
                                                              policy.id))

        response_octets = response.json["ip_octets"]
        self.assertEqual(len(response_octets), 3)
        self.assertItemsEqual(response_octets,
                              _data(policy.unusable_ip_octets))

    def test_index_with_pagination(self):
        policy = factory_models.PolicyFactory(tenant_id="tnt_id")
        ip_octets = [factory_models.IpOctetFactory(policy_id=policy.id)
                     for i in range(0, 5)]
        ip_octets = models.sort(ip_octets)

        response = self.app.get("%s/%s/unusable_ip_octets?limit=2&marker=%s"
                                % (self.policy_path,
                                   policy.id,
                                   ip_octets[0].id))

        next_link = response.json["ip_octets_links"][0]['href']
        expected_next_link = string.replace(response.request.url,
                                            "marker=%s" % ip_octets[0].id,
                                            "marker=%s" % ip_octets[2].id)

        response_octets = response.json["ip_octets"]
        self.assertEqual(len(response_octets), 2)
        self.assertItemsEqual(response_octets, _data(ip_octets[1:3]))
        self.assertUrlEqual(next_link, expected_next_link)

    def test_index_fails_for_non_existent_policy_for_given_tenant(self):
        policy = factory_models.PolicyFactory(tenant_id="tnt_id")
        self.policy_path = "/ipam/tenants/another_tenant_id/policies"
        response = self.app.get("%s/%s/unusable_ip_octets"
                                % (self.policy_path, policy.id),
                                status='*')

        self.assertErrorResponse(response, webob.exc.HTTPNotFound,
                                 "Policy Not Found")

    def test_create(self):
        policy = factory_models.PolicyFactory(tenant_id="tnt_id")
        response = self.app.post_json("%s/%s/unusable_ip_octets"
                                      % (self.policy_path, policy.id),
                                      {'ip_octet': {'octet': '123'}})

        ip_octet = models.IpOctet.find_by(policy_id=policy.id)
        self.assertEqual(response.status, "201 Created")
        self.assertEqual(response.json['ip_octet'], _data(ip_octet))

    def test_create_on_non_existent_policy(self):
        response = self.app.post_json("%s/bad_policy_id/unusable_ip_octets"
                                      % self.policy_path,
                                      {'ip_octet': {'octet': '2'}},
                                      status="*")

        self.assertErrorResponse(response, webob.exc.HTTPNotFound,
                                 "Policy Not Found")

    def test_create_fails_for_non_existent_policy_for_given_tenant(self):
        policy = factory_models.PolicyFactory(tenant_id="tnt_id")
        self.policy_path = "/ipam/tenants/another_tenant_id/policies"
        response = self.app.post_json("%s/%s/unusable_ip_octets"
                                      % (self.policy_path, policy.id),
                                      {'ip_octet': {'octet': 1}},
                                      status='*')

        self.assertErrorResponse(response, webob.exc.HTTPNotFound,
                                 "Policy Not Found")

    def test_show(self):
        policy = factory_models.PolicyFactory(tenant_id="tnt_id")
        ip_octet = factory_models.IpOctetFactory(policy_id=policy.id)

        response = self.app.get("%s/%s/unusable_ip_octets/%s"
                                % (self.policy_path, policy.id, ip_octet.id))

        self.assertEqual(response.status_int, 200)
        self.assertEqual(response.json['ip_octet'], _data(ip_octet))

    def test_show_when_ip_octet_does_not_exists(self):
        policy = factory_models.PolicyFactory(tenant_id="tnt_id")

        response = self.app.get("%s/%s/unusable_ip_octets/non_existant_octet"
                                % (self.policy_path, policy.id),
                                status="*")

        self.assertErrorResponse(response, webob.exc.HTTPNotFound,
                                 "IpOctet Not Found")

    def test_show_fails_for_non_existent_policy_for_given_tenant(self):
        policy = factory_models.PolicyFactory(tenant_id="tnt_id")
        ip_octet = factory_models.IpOctetFactory(policy_id=policy.id)
        self.policy_path = "/ipam/tenants/another_tenanat_id/policies"
        response = self.app.get("%s/%s/unusable_ip_octets/%s"
                                % (self.policy_path, policy.id, ip_octet.id),
                                status='*')

        self.assertErrorResponse(response, webob.exc.HTTPNotFound,
                                 "Policy Not Found")

    def test_update(self):
        policy = factory_models.PolicyFactory(tenant_id="tnt_id")
        ip_octet = factory_models.IpOctetFactory.create(octet=10,
                                                        policy_id=policy.id)

        response = self.app.put_json("%s/%s/unusable_ip_octets/%s"
                                     % (self.policy_path,
                                        policy.id,
                                        ip_octet.id),
                                     {'ip_octet': {'octet': 123}})

        self.assertEqual(response.status_int, 200)
        updated_octet = models.IpOctet.find(ip_octet.id)
        self.assertEqual(updated_octet.octet, 123)
        self.assertEqual(response.json['ip_octet'], _data(updated_octet))

    def test_update_ignores_change_in_policy_id(self):
        policy = factory_models.PolicyFactory(tenant_id="tnt_id")
        ip_octet = factory_models.IpOctetFactory.create(octet=254,
                                                        policy_id=policy.id)
        new_policy_id = utils.generate_uuid()
        response = self.app.put_json("%s/%s/unusable_ip_octets/%s"
                                % (self.policy_path, policy.id, ip_octet.id),
                                {'ip_octet': {
                                         'octet': 253,
                                         'policy_id': new_policy_id,
                                         },
                                 })

        self.assertEqual(response.status_int, 200)
        updated_octet = models.IpOctet.find(ip_octet.id)
        self.assertEqual(updated_octet.octet, 253)
        self.assertEqual(updated_octet.policy_id, policy.id)
        self.assertEqual(response.json['ip_octet']['policy_id'], policy.id)

    def test_update_fails_for_non_existent_policy_for_given_tenant(self):
        policy = factory_models.PolicyFactory(tenant_id="tnt_id")
        ip_octet = factory_models.IpOctetFactory(policy_id=policy.id)
        self.policy_path = "/ipam/tenants/another_tenant_id/policies"
        response = self.app.put_json("%s/%s/unusable_ip_octets/%s"
                                     % (self.policy_path,
                                        policy.id,
                                        ip_octet.id),
                                     {'ip_octet': {'octet': 1}},
                                     status='*')

        self.assertErrorResponse(response, webob.exc.HTTPNotFound,
                                 "Policy Not Found")

    def test_update_when_ip_octet_does_not_exists(self):
        policy = factory_models.PolicyFactory(tenant_id="tnt_id")

        response = self.app.put_json("%s/%s/unusable_ip_octets/invalid_id"
                                     % (self.policy_path, policy.id),
                                     {'ip_octet': {'octet': 222}},
                                     status="*")

        self.assertErrorResponse(response, webob.exc.HTTPNotFound,
                                 "IpOctet Not Found")

    def test_delete(self):
        policy = factory_models.PolicyFactory(tenant_id="tnt_id")
        ip_octet = factory_models.IpOctetFactory(policy_id=policy.id)

        response = self.app.delete("%s/%s/unusable_ip_octets/%s"
                                   % (self.policy_path,
                                      policy.id,
                                      ip_octet.id))

        self.assertEqual(response.status_int, 200)
        self.assertRaises(models.ModelNotFoundError,
                          policy.find_ip_octet,
                          ip_octet_id=ip_octet.id)

    def test_delete_fails_for_non_existent_policy_for_given_tenant(self):
        policy = factory_models.PolicyFactory(tenant_id="tnt_id")
        ip_octet = factory_models.IpOctetFactory(policy_id=policy.id)
        self.policy_path = "/ipam/tenants/another_tenant_id/policies"
        response = self.app.delete("%s/%s/unusable_ip_octets/%s"
                                   % (self.policy_path,
                                      policy.id,
                                      ip_octet.id),
                                   status='*')

        self.assertErrorResponse(response, webob.exc.HTTPNotFound,
                                 "Policy Not Found")


class TestTenantPoliciesController(BaseTestController):

    def test_index(self):
        policy1 = factory_models.PolicyFactory(tenant_id="1")
        policy2 = factory_models.PolicyFactory(tenant_id="2")
        policy3 = factory_models.PolicyFactory(tenant_id="1")

        response = self.app.get("/ipam/tenants/1/policies")

        self.assertEqual(response.status_int, 200)
        self.assertItemsEqual(response.json["policies"],
                              _data([policy1, policy3]))

    def test_create(self):
        response = self.app.post_json("/ipam/tenants/1111/policies",
                                      {'policy': {'name': "infrastructure"}})

        self.assertTrue(models.Policy.find_by(tenant_id="1111") is not None)
        self.assertEqual(response.status, "201 Created")
        self.assertEqual(response.json['policy']['tenant_id'], "1111")

    def test_create_ignores_tenant_id_passed_in_post_body(self):
        response = self.app.post_json("/ipam/tenants/123/policies",
                                      {'policy': {'name': "Standard",
                                                  'tenant_id': "124"}})

        self.assertEqual(response.status_int, 201)
        self.assertEqual(response.json['policy']['name'], "Standard")
        self.assertEqual(response.json['policy']['tenant_id'], "123")

    def test_show(self):
        policy = factory_models.PolicyFactory(tenant_id="1111")
        response = self.app.get("/ipam/tenants/1111/policies/%s" % policy.id)

        self.assertEqual(response.status, "200 OK")
        self.assertEqual(response.json['policy']['id'], policy.id)

    def test_show_fails_for_nonexistent_tenant(self):
        policy = factory_models.PolicyFactory(tenant_id="1112")
        response = self.app.get("/ipam/tenants/1111/policies/%s" % policy.id,
                                status="*")

        self.assertErrorResponse(response, webob.exc.HTTPNotFound,
                                 "Policy Not Found")

    def test_update_fails_for_incorrect_tenant_id(self):
        policy = factory_models.PolicyFactory(tenant_id="111")
        response = self.app.put_json("/ipam/tenants/123/policies/%s"
                                     % policy.id,
                                     {'policy': {'name': "Standard"}},
                                     status="*")

        self.assertErrorResponse(response, webob.exc.HTTPNotFound,
                                 "Policy Not Found")

    def test_update(self):
        policy = factory_models.PolicyFactory(name="blah", tenant_id="123")
        response = self.app.put_json("/ipam/tenants/123/policies/%s"
                                     % policy.id,
                                     {'policy': {'name': "Standard"}})

        self.assertEqual(response.status_int, 200)
        self.assertEqual("Standard", models.Policy.find(policy.id).name)

    def test_update_cannot_change_tenant_id(self):
        policy = factory_models.PolicyFactory(name="Infrastructure",
                                              tenant_id="123")
        response = self.app.put_json("/ipam/tenants/123/policies/%s"
                                     % policy.id,
                                     {'policy': {'name': "Standard",
                                                 'tenant_id': "124",
                                                 },
                                      })

        self.assertEqual(response.status_int, 200)
        updated_policy = models.Policy.find(policy.id)
        self.assertEqual(updated_policy.name, "Standard")
        self.assertEqual(updated_policy.tenant_id, "123")
        self.assertEqual(response.json['policy']['tenant_id'], "123")

    def test_delete(self):
        policy = factory_models.PolicyFactory(tenant_id="123")
        response = self.app.delete("/ipam/tenants/123/policies/%s" % policy.id)

        self.assertEqual(response.status_int, 200)
        self.assertTrue(models.Policy.get(policy.id) is None)

    def test_delete_fails_for_incorrect_tenant_id(self):
        policy = factory_models.PolicyFactory(tenant_id="123")
        response = self.app.delete("/ipam/tenants/111/policies/%s" % policy.id,
                                   status="*")

        self.assertErrorResponse(response, webob.exc.HTTPNotFound,
                                 "Policy Not Found")


class TestNetworksController(BaseTestController):

    def setUp(self):
        self.network_path = "/ipam/tenants/tnt_id"
        super(TestNetworksController, self).setUp()

    def test_allocate_ip_address(self):
        ip_block = factory_models.PrivateIpBlockFactory(tenant_id="tnt_id",
                                                        network_id=1)

        response = self.app.post("{0}/networks/1/interfaces/123/"
                                 "ip_allocations".format(self.network_path))

        ip_address = models.IpAddress.find_by(ip_block_id=ip_block.id)
        self.assertEqual(response.status_int, 201)
        self.assertEqual([_data(ip_address, with_ip_block=True)],
                         response.json['ip_addresses'])
        self.assertEqual(ip_address.interface_id, "123")

    def test_allocate_ip_with_given_address(self):
        ip_block = factory_models.PrivateIpBlockFactory(tenant_id="tnt_id",
                                                        network_id=1,
                                                        cidr="10.0.0.0/24")

        response = self.app.post_json("{0}/networks/1/interfaces/123"
                                 "/ip_allocations".format(self.network_path),
                                 {'network': {'addresses': ['10.0.0.2']}})

        ip_address = models.IpAddress.find_by(ip_block_id=ip_block.id,
                                              address="10.0.0.2")
        self.assertEqual(response.status_int, 201)
        self.assertEqual([_data(ip_address, with_ip_block=True)],
                         response.json['ip_addresses'])

    def test_allocate_ip_with_optional_params(self):
        ip_block = factory_models.PrivateIpBlockFactory(tenant_id="tnt_id",
                                                        network_id=1,
                                                        cidr="10.0.0.0/24")

        response = self.app.post_json("{0}/networks/1/interfaces/123"
                                 "/ip_allocations".format(self.network_path),
                                 {'network': {
                                          'tenant_id': "RAX",
                                          'used_by_device': "instance_id"
                                          }
                                  })

        ip_address = models.IpAddress.find_by(ip_block_id=ip_block.id)
        self.assertEqual(ip_address.used_by_tenant, "RAX")
        self.assertEqual(ip_address.used_by_device, "instance_id")

    def test_allocate_ip_allocates_v6_address_with_given_params(self):
        mac_address = "11:22:33:44:55:66"
        ipv6_generator = mock_generator.MockIpV6Generator("fe::/96")
        ipv6_block = factory_models.PrivateIpBlockFactory(tenant_id="tnt_id",
                                                          network_id=1,
                                                          cidr="fe::/96")
        self.mock.StubOutWithMock(ipv6, "address_generator_factory")
        ipv6.address_generator_factory("fe::/96",
                                       mac_address=mac_address,
                                       used_by_tenant="tnt_id").\
                                       AndReturn(ipv6_generator)

        self.mock.ReplayAll()

        response = self.app.post_json("{0}/networks/1/interfaces/123"
                                   "/ip_allocations".format(self.network_path),
                                    {'network': {'mac_address': mac_address,
                                                 'tenant_id': "tnt_id",
                                                 },
                                     })

        ipv6_address = models.IpAddress.find_by(ip_block_id=ipv6_block.id)
        self.assertEqual([_data(ipv6_address, with_ip_block=True)],
                         response.json['ip_addresses'])

    def test_deallocate_ips(self):
        ip_block = factory_models.PrivateIpBlockFactory(tenant_id="tnt_id",
                                                        network_id=1)

        ip = ip_block.allocate_ip(interface_id=123)

        response = self.app.delete("{0}/networks/1/interfaces/123/"
                                   "ip_allocations".format(self.network_path))

        ip_address = models.IpAddress.get(ip.id)
        self.assertEqual(response.status_int, 200)
        self.assertTrue(ip_address.marked_for_deallocation)

    def test_deallocate_ip_when_network_does_not_exist(self):
        response = self.app.delete("{0}/networks/1/interfaces/123/"
                                   "ip_allocations".format(self.network_path),
                                   status="*")

        self.assertErrorResponse(response, webob.exc.HTTPNotFound,
                                 "Network 1 not found")

    def test_get_allocated_ips(self):
        factory = factory_models.PrivateIpBlockFactory
        ipv4_block = factory(cidr="10.0.0.0/8",
                             network_id=1,
                             tenant_id="tnt_id")
        ipv6_block = factory(cidr="fe::/96", network_id=1, tenant_id="tnt_id")
        ip1 = ipv4_block.allocate_ip(interface_id="123")
        ip2 = ipv4_block.allocate_ip(interface_id="123")
        ip3 = ipv6_block.allocate_ip(interface_id="123",
                                      mac_address="aa:bb:cc:dd:ee:ff",
                                      used_by_tenant=ipv6_block.tenant_id)

        response = self.app.get("{0}/networks/1/interfaces/123/"
                                "ip_allocations".format(self.network_path))
        self.assertEqual(response.status_int, 200)
        self.assertItemsEqual(_data([ip1, ip2, ip3], with_ip_block=True),
                              response.json["ip_addresses"])

    def test_allocate_ip_creates_network_if_network_not_found(self):
        response = self.app.post("/ipam/tenants/tnt_id/networks/1"
                                 "/interfaces/123/ip_allocations")

        self.assertEqual(response.status_int, 201)
        ip_address_json = response.json['ip_addresses'][0]
        ip_block = models.IpBlock.find(ip_address_json['ip_block_id'])
        self.assertEqual(ip_block.network_id, "1")
        self.assertEqual(ip_block.cidr, config.Config.get('default_cidr'))
        self.assertEqual(ip_block.type, "private")
        self.assertEqual(ip_block.tenant_id, "tnt_id")


def _allocate_ips(*args):
    return [models.sort([ip_block.allocate_ip() for i in range(num_of_ips)])
            for ip_block, num_of_ips in args]


def _data(resource, **options):
    if isinstance(resource, models.ModelBase):
        return unit.sanitize(resource.data(**options))
    return [_data(model, **options) for model in resource]
