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
import string
import unittest
from webob.exc import HTTPBadRequest
from webob.exc import HTTPNotFound
from webob.exc import HTTPUnprocessableEntity

from melange.common import config
from melange.common import utils
from melange.common import wsgi
from melange.common.config import Config
from melange.ipam import models
from melange.ipam.models import IpAddress
from melange.ipam.models import IpBlock
from melange.ipam.models import IpOctet
from melange.ipam.models import IpRange
from melange.ipam.models import Policy
from melange.ipam.service import BaseController
from melange.tests import BaseTest
from melange.tests.factories.models import IpAddressFactory
from melange.tests.factories.models import IpBlockFactory
from melange.tests.factories.models import IpOctetFactory
from melange.tests.factories.models import IpRangeFactory
from melange.tests.factories.models import PolicyFactory
from melange.tests.factories.models import PrivateIpBlockFactory
from melange.tests.factories.models import PublicIpBlockFactory
from melange.tests.unit import sanitize
from melange.tests.unit import test_config_path
from melange.tests.unit import TestApp
from melange.tests.unit.mock_generator import MockIpV6Generator


class BaseTestController(BaseTest):

    def setUp(self):
        super(BaseTestController, self).setUp()
        conf, melange_app = config.load_paste_app('melange',
                {"config_file": test_config_path()}, None)
        self.app = TestApp(melange_app)


class DummyApp(wsgi.Router):

    def __init__(self):
        mapper = routes.Mapper()
        mapper.resource("resource", "/resources", controller=StubController())
        super(DummyApp, self).__init__(mapper)


class StubController(BaseController):
    def index(self, request, format=None):
        raise self.exception


class TestBaseController(unittest.TestCase):
    def _assert_mapping(self, exception, http_code):
        StubController.exception = exception
        app = TestApp(DummyApp())

        response = app.get("/resources", status="*")
        self.assertEqual(response.status_int, http_code)

    def test_exception_to_http_code_mapping(self):
        self._assert_mapping(models.InvalidModelError(None), 400)
        self._assert_mapping(models.DataMissingError, 400)
        self._assert_mapping(models.ModelNotFoundError, 404)
        self._assert_mapping(models.NoMoreAddressesError, 422)
        self._assert_mapping(models.AddressDoesNotBelongError, 422)
        self._assert_mapping(models.AddressLockedError, 422)
        self._assert_mapping(models.DuplicateAddressError, 409)

    def test_http_excpetions_are_bubbled_up(self):
        self._assert_mapping(HTTPUnprocessableEntity, 422)
        self._assert_mapping(HTTPNotFound, 404)


class IpBlockControllerBase():

    def test_create_with_bad_cidr(self):
        response = self.app.post_json("%s" % self.ip_block_path,
                          {'ip_block': {'network_id': "300", 'type': "public",
                                        'cidr': "10..."}},
                          status="*")

        self.assertErrorResponse(response, HTTPBadRequest,
                                 'cidr is invalid')

    def test_create_ignores_uneditable_fields(self):
        response = self.app.post_json("%s" % self.ip_block_path,
                                 {'ip_block': {'network_id': "300",
                                  'cidr': "10.0.0.0/31", 'type': "public",
                                    'parent_id': 'input_parent_id',
                                    'tenant_id': 'input_tenant_id'}},
                                 status="*")

        self.assertEqual(response.status_int, 201)
        created_block = IpBlock.find_by(network_id="300")
        self.assertNotEqual(created_block.type, "Ignored")
        self.assertNotEqual(created_block.parent_id, "input_parent_id")
        self.assertNotEqual(created_block.tenant_id, "input_tenant_id")

    def test_show(self):
        block = IpBlockFactory(**self._ip_block_args())
        response = self.app.get("%s/%s" % (self.ip_block_path, block.id))

        self.assertEqual(response.status, "200 OK")
        self.assertEqual(response.json['ip_block'], _data(block))

    def test_update(self):
        old_policy = PolicyFactory()
        new_policy = PolicyFactory()
        block = IpBlockFactory(**self._ip_block_args(network_id="net1",
                               policy_id=old_policy.id))

        response = self.app.put_json("%s/%s" % (self.ip_block_path, block.id),
                                     {'ip_block': {'network_id': "new_net",
                                                  'policy_id': new_policy.id}})
        updated_block = IpBlock.find(block.id)
        self.assertEqual(response.status_int, 200)
        self.assertEqual(updated_block.network_id, "new_net")
        self.assertEqual(updated_block.policy_id, new_policy.id)

        self.assertEqual(response.json,
                         dict(ip_block=_data(updated_block)))

    def test_update_to_exclude_uneditable_fields(self):
        parent = IpBlockFactory(**self._ip_block_args(cidr="10.0.0.0/28"))
        another = IpBlockFactory(cidr="20.0.0.0/28")
        block = IpBlockFactory(**self._ip_block_args(cidr="10.0.0.0/29",
                                                   parent_id=parent.id))

        response = self.app.put_json("%s/%s" % (self.ip_block_path, block.id),
                                     {'ip_block': {'type': "new_type",
                                                  'cidr': "50.0.0.0/29",
                                                   'tenant_id': "new_tenant",
                                                   'parent_id': another.id}})
        updated_block = IpBlock.find(block.id)
        self.assertEqual(response.status_int, 200)
        self.assertEqual(updated_block.cidr, "10.0.0.0/29")
        self.assertNotEqual(updated_block.tenant_id, "new_tenant")
        self.assertNotEqual(updated_block.parent_id, another.id)
        self.assertNotEqual(updated_block.type, "new_type")

        self.assertEqual(response.json, dict(ip_block=_data(updated_block)))

    def test_delete(self):
        block = IpBlockFactory(**self._ip_block_args())
        response = self.app.delete("%s/%s" % (self.ip_block_path, block.id))

        self.assertEqual(response.status, "200 OK")
        self.assertRaises(models.ModelNotFoundError, IpBlock.find, block.id)

    def test_index(self):
        blocks = [PublicIpBlockFactory(
                   **self._ip_block_args(cidr="192.1.1.1/30", network_id="1")),
                  PrivateIpBlockFactory(
                   **self._ip_block_args(cidr="192.2.2.2/30", network_id="2")),
                  PublicIpBlockFactory(
                   **self._ip_block_args(cidr="192.3.3.3/30", network_id="1"))]
        response = self.app.get("%s" % self.ip_block_path)

        self.assertEqual(response.status, "200 OK")
        response_blocks = response.json['ip_blocks']
        self.assertEqual(len(response_blocks), 3)
        self.assertItemsEqual(response_blocks, _data(blocks))

    def test_index_is_able_to_filter_by_type(self):
        PublicIpBlockFactory(**self._ip_block_args(cidr="72.1.1.1/30",
                                                 network_id="1"))
        private_blocks = [PrivateIpBlockFactory(
                **self._ip_block_args(cidr="12.2.2.2/30", network_id="2")),
                          PrivateIpBlockFactory(
                **self._ip_block_args(cidr="192.3.3.3/30", network_id="2"))]

        response = self.app.get("%s" % self.ip_block_path, {'type': "private"})

        self.assertEqual(response.status, "200 OK")
        response_blocks = response.json['ip_blocks']
        self.assertEqual(len(response_blocks), 2)
        self.assertItemsEqual(response_blocks, _data(private_blocks))

    def test_index_with_pagination(self):
        blocks = [IpBlockFactory(**self._ip_block_args(cidr="10.1.1.0/28")),
                  IpBlockFactory(**self._ip_block_args(cidr='10.2.1.0/28')),
                  IpBlockFactory(**self._ip_block_args(cidr='10.3.1.0/28')),
                  IpBlockFactory(**self._ip_block_args(cidr='10.4.1.0/28')),
                  IpBlockFactory(**self._ip_block_args(cidr='10.5.1.0/28'))]

        blocks = models.sort(blocks)

        response = self.app.get("%s?limit=2&marker=%s"
                                % (self.ip_block_path, blocks[1].id))

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
        blocks = [IpBlockFactory(**self._ip_block_args(cidr="10.1.1.0/28")),
                  IpBlockFactory(**self._ip_block_args(cidr='10.2.1.0/28')),
                  IpBlockFactory(**self._ip_block_args(cidr='10.3.1.0/28')),
                  IpBlockFactory(**self._ip_block_args(cidr='10.4.1.0/28'))]

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
        blocks = [IpBlockFactory(**self._ip_block_args(cidr="10.1.1.0/28")),
                  IpBlockFactory(**self._ip_block_args(cidr='10.2.1.0/28')),
                  IpBlockFactory(**self._ip_block_args(cidr='10.3.1.0/28'))]

        blocks = models.sort(blocks)

        response = self.app.get("%s?limit=2&marker=%s"
                                % (self.ip_block_path, blocks[0].id))

        response_blocks = response.json['ip_blocks']
        self.assertEqual(response.status, "200 OK")
        self.assertEqual(len(response_blocks), 2)
        self.assertTrue("ip_blocks_links" not in response.json)


class TestGlobalIpBlockController(IpBlockControllerBase, BaseTestController):

    def setUp(self):
        self.ip_block_path = "/ipam/ip_blocks"
        super(TestGlobalIpBlockController, self).setUp()

    def _ip_block_args(self, **kwargs):
        kwargs['tenant_id'] = None
        return kwargs

    def test_create(self):
        response = self.app.post_json("/ipam/ip_blocks.json",
                                 {'ip_block': {'network_id': "300",
                                               'cidr': "10.1.1.0/24",
                                               'type': "private",
                                               'dns1': "12.34.56.67",
                                               'dns2': "65.76.87.98"}})

        self.assertEqual(response.status, "201 Created")
        saved_block = IpBlock.find_by(network_id="300")
        self.assertEqual(saved_block.cidr, "10.1.1.0/24")
        self.assertEqual(saved_block.type, "private")
        self.assertEqual(saved_block.tenant_id, None)
        self.assertEqual(saved_block.dns1, "12.34.56.67")
        self.assertEqual(saved_block.dns2, "65.76.87.98")
        self.assertEqual(response.json, dict(ip_block=_data(saved_block)))


class TestTenantBasedIpBlockController(IpBlockControllerBase,
                                        BaseTestController):

    def setUp(self):
        self.ip_block_path = "/ipam/tenants/123/ip_blocks"
        super(TestTenantBasedIpBlockController, self).setUp()

    def _ip_block_args(self, **kwargs):
        kwargs['tenant_id'] = "123"
        return kwargs

    def test_create(self):
        response = self.app.post_json(
                     "/ipam/tenants/111/ip_blocks.json",
                     {'ip_block': {'network_id': "3", 'cidr': "10.1.1.0/24",
                                   'type': "public",
                                   'dns1': "12.34.56.67",
                                   'dns2': "65.76.87.98"}})

        self.assertEqual(response.status, "201 Created")
        saved_block = IpBlock.find_by(network_id="3")
        self.assertEqual(saved_block.cidr, "10.1.1.0/24")
        self.assertEqual(saved_block.type, "public")
        self.assertEqual(saved_block.tenant_id, "111")
        self.assertEqual(saved_block.dns1, "12.34.56.67")
        self.assertEqual(saved_block.dns2, "65.76.87.98")
        self.assertEqual(response.json, dict(ip_block=_data(saved_block)))

    def test_create_ignores_tenant_id_passed_in_post_body(self):
        response = self.app.post_json("/ipam/tenants/111/ip_blocks",
                       {'ip_block': {'network_id': "300", 'cidr': "10.1.1.0/2",
                                     'tenant_id': "543", 'type': "public"}})

        saved_block = IpBlock.find_by(network_id="300")
        self.assertEqual(saved_block.tenant_id, "111")
        self.assertEqual(response.json, dict(ip_block=_data(saved_block)))

    def test_show_fails_if_block_does_not_belong_to_tenant(self):
        block = PrivateIpBlockFactory(tenant_id='0000')
        response = self.app.get("/ipam/tenants/112/ip_blocks/%s"
                                % block.id, status='*')

        self.assertEqual(response.status, "404 Not Found")

    def test_index_scoped_by_tenant(self):
        ip_block1 = PrivateIpBlockFactory(cidr="10.0.0.1/8", tenant_id='999')
        ip_block2 = PrivateIpBlockFactory(cidr="10.0.0.2/8", tenant_id='999')
        PrivateIpBlockFactory(cidr="10.1.1.1/2", tenant_id='987')

        response = self.app.get("/ipam/tenants/999/ip_blocks")

        self.assertEqual(response.status, "200 OK")
        response_blocks = response.json['ip_blocks']
        self.assertEqual(len(response_blocks), 2)
        self.assertItemsEqual(response_blocks, _data([ip_block1, ip_block2]))

    def test_update_fails_for_non_existent_block_for_given_tenant(self):
        ip_block = PrivateIpBlockFactory(tenant_id="123")
        response = self.app.put_json("/ipam/tenants/321/ip_blocks/%s"
                                     % ip_block.id, {'ip_block':
                                                      {'network_id': "foo"}},
                                                  status='*')

        self.assertErrorResponse(response, HTTPNotFound, "IpBlock Not Found")


class SubnetControllerBase(object):

    def test_index(self):
        parent = self._ip_block_factory(cidr="10.0.0.0/28")
        subnet1 = self._ip_block_factory(cidr="10.0.0.0/29",
                                         parent_id=parent.id)
        subnet2 = self._ip_block_factory(cidr="10.0.0.8/29",
                                         parent_id=parent.id)

        response = self.app.get(self._subnets_path(parent))

        self.assertEqual(response.status_int, 200)
        self.assertItemsEqual(response.json['subnets'],
                              _data([subnet1, subnet2]))

    def test_create(self):
        parent = self._ip_block_factory(cidr="10.0.0.0/28")

        response = self.app.post_json(self._subnets_path(parent),
                                 {'subnet': {'cidr': "10.0.0.0/29",
                                             'network_id': "2"}})

        subnet = IpBlock.find_by(parent_id=parent.id)
        self.assertEqual(response.status_int, 201)
        self.assertEqual(subnet.network_id, "2")
        self.assertEqual(subnet.cidr, "10.0.0.0/29")
        self.assertEqual(response.json['subnet'], _data(subnet))

    def test_create_excludes_uneditable_fields(self):
        parent = self._ip_block_factory(cidr="10.0.0.0/28")

        response = self.app.post_json(self._subnets_path(parent),
                                 {'subnet': {'cidr': "10.0.0.0/29",
                                             'type': "Input type",
                                             'parent_id': "Input parent"}})

        subnet = IpBlock.find_by(parent_id=parent.id)
        self.assertEqual(response.status_int, 201)
        self.assertNotEqual(subnet.type, "Input type")
        self.assertNotEqual(subnet.parent_id, "Input parent")


class TestGlobalSubnetController(BaseTestController,
                                 SubnetControllerBase):

    def _ip_block_factory(self, **kwargs):
        return IpBlockFactory(**kwargs)

    def _subnets_path(self, ip_block):
        return "/ipam/ip_blocks/{0}/subnets".format(ip_block.id)

    def test_create_for_the_given_tenant(self):
        parent = self._ip_block_factory(cidr="10.0.0.0/28")

        response = self.app.post_json(self._subnets_path(parent),
                                 {'subnet': {'cidr': "10.0.0.0/29",
                                             'tenant_id': "2"}})

        subnet = IpBlock.find_by(parent_id=parent.id)
        self.assertEqual(response.status_int, 201)
        self.assertEqual(subnet.tenant_id, "2")


class TestTenantBasedSubnetController(BaseTestController,
                                 SubnetControllerBase):

    def _ip_block_factory(self, **kwargs):
        kwargs['tenant_id'] = kwargs.get('tenant_id', "1")
        return IpBlockFactory(**kwargs)

    def _subnets_path(self, ip_block):
        return "/ipam/tenants/1/ip_blocks/{0}/subnets".format(ip_block.id)

    def test_create_for_the_another_tenant_fails(self):
        parent = self._ip_block_factory(cidr="10.0.0.0/28", tenant_id="1")

        response = self.app.post_json(self._subnets_path(parent),
                                 {'subnet': {'cidr': "10.0.0.0/29",
                                             'tenant_id': "2"}}, status="4*")

        self.assertErrorResponse(response, HTTPBadRequest,
                                 "tenant_id should be same as that of parent")


class IpAddressControllerBase(object):

    def test_create(self):
        block = self.ip_block_factory(cidr="10.1.1.0/28")
        response = self.app.post(self.address_path(block))

        self.assertEqual(response.status, "201 Created")
        allocated_address = IpAddress.find_by(ip_block_id=block.id)
        self.assertEqual(allocated_address.address, "10.1.1.0")
        self.assertEqual(response.json,
                         dict(ip_address=_data(allocated_address)))

    def test_create_with_given_address(self):
        block = self.ip_block_factory(cidr="10.1.1.0/28")
        response = self.app.post_json(self.address_path(block),
                                      {'ip_address': {"address": '10.1.1.2'}})

        self.assertEqual(response.status, "201 Created")
        self.assertNotEqual(IpAddress.find_by(ip_block_id=block.id,
                                              address="10.1.1.2"), None)

    def test_create_with_interface(self):
        block = self.ip_block_factory()

        self.app.post_json(self.address_path(block),
                           {'ip_address': {"interface_id": "1111"}})

        allocated_address = IpAddress.find_by(ip_block_id=block.id)
        self.assertEqual(allocated_address.interface_id, "1111")

    def test_create_ipv6_address_fails_when_mac_address_not_given(self):
        block = self.ip_block_factory(cidr="ff::/64")

        response = self.app.post_json(self.address_path(block),
                                      {'ip_address': {"interface_id": "1111"}},
                                      status="*")

        self.assertErrorResponse(response, HTTPBadRequest,
                                 "Required params are missing: mac_address")

    def test_create_passes_request_params_to_ipv6_allocation_algorithm(self):
        block = self.ip_block_factory(cidr="ff::/64")
        params = {'ip_address': {"interface_id": "123",
                                 'mac_address': "10:23:56:78:90:01",
                                 'tenant_id': "111"}}
        generated_ip = IpAddressFactory(address="ff::1", ip_block_id=block.id)
        self.mock.StubOutWithMock(IpBlock, "allocate_ip")
        IpBlock.allocate_ip(interface_id="123",
                            mac_address="10:23:56:78:90:01",
                            tenant_id="111").AndReturn(generated_ip)

        self.mock.ReplayAll()
        response = self.app.post_json(self.address_path(block), params)

        self.assertEqual(response.status_int, 201)

    def test_show(self):
        block = self.ip_block_factory(cidr='10.1.1.1/30')
        ip = block.allocate_ip(interface_id="3333")

        response = self.app.get("{0}/{1}.json".format(self.address_path(block),
                                                      ip.address))

        self.assertEqual(response.status, "200 OK")
        self.assertEqual(response.json, dict(ip_address=_data(ip)))

    def test_show_fails_for_nonexistent_address(self):
        block = self.ip_block_factory(cidr="10.1.1.0/28")

        response = self.app.get("{0}/{1}".format(self.address_path(block),
                                                      '10.1.1.0'), status="*")

        self.assertEqual(response.status, "404 Not Found")
        self.assertTrue("IpAddress Not Found" in response.body)

    def test_delete_ip(self):
        block = self.ip_block_factory(cidr='10.1.1.1/30')
        ip = block.allocate_ip()

        response = self.app.delete("{0}/{1}.xml".format(
                self.address_path(block), ip.address))

        self.assertEqual(response.status, "200 OK")
        self.assertIsNotNone(IpAddress.find(ip.id))
        self.assertTrue(IpAddress.find(ip.id).marked_for_deallocation)

    def test_index(self):
        block = self.ip_block_factory()
        address_1, address_2 = models.sort([block.allocate_ip()
                                            for i in range(2)])

        response = self.app.get(self.address_path(block))

        ip_addresses = response.json["ip_addresses"]
        self.assertEqual(response.status, "200 OK")
        self.assertEqual(len(ip_addresses), 2)
        self.assertEqual(ip_addresses[0]['address'], address_1.address)
        self.assertEqual(ip_addresses[1]['address'], address_2.address)

    def test_index_with_pagination(self):
        block = self.ip_block_factory()
        ips = models.sort([block.allocate_ip() for i in range(5)])

        response = self.app.get("{0}?limit=2&marker={1}".format(
                self.address_path(block), ips[1].id))

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
        block = self.ip_block_factory()
        ips = [block.allocate_ip() for i in range(5)]
        block.deallocate_ip(ips[0].address)

        response = self.app.put("{0}/{1}/restore".format(
                self.address_path(block), ips[0].address))

        ip_addresses = [ip.address for ip in
                        IpAddress.find_all(ip_block_id=block.id)]
        self.assertEqual(response.status, "200 OK")
        self.assertItemsEqual(ip_addresses, [ip.address for ip in ips])


class TestTenantBasedIpAddressController(IpAddressControllerBase,
                                         BaseTestController):

    def ip_block_factory(self, **kwargs):
        kwargs['tenant_id'] = '111'
        return IpBlockFactory(**kwargs)

    def address_path(self, block):
        return ("/ipam/tenants/111/ip_blocks/{0}/"
                "ip_addresses".format(block.id))

    def test_show_fails_for_non_existent_block_for_given_tenant(self):
        block = IpBlockFactory(tenant_id=123)
        ip_address = IpAddressFactory(ip_block_id=block.id)
        self.block_path = "/ipam/tenants/111/ip_blocks"
        response = self.app.get("%s/%s/ip_addresses/%s"
                                 % (self.block_path, block.id,
                                    ip_address.address), status='*')

        self.assertErrorResponse(response, HTTPNotFound, "IpBlock Not Found")

    def test_index_fails_for_non_existent_block_for_given_tenant(self):
        block = IpBlockFactory(tenant_id=123)
        ip_address = IpAddressFactory(ip_block_id=block.id)

        self.block_path = "/ipam/tenants/111/ip_blocks"
        response = self.app.get("%s/%s/ip_addresses"
                                 % (self.block_path, block.id),
                                 status='*')

        self.assertErrorResponse(response, HTTPNotFound, "IpBlock Not Found")

    def test_restore_fails_for_non_existent_block_for_given_tenant(self):
        block = IpBlockFactory(tenant_id=123)
        ip_address = IpAddressFactory(ip_block_id=block.id)
        block.deallocate_ip(ip_address.address)
        self.block_path = "/ipam/tenants/111/ip_blocks"
        response = self.app.put("%s/%s/ip_addresses/%s/restore"
                                 % (self.block_path, block.id,
                                    ip_address.address),
                                 status='*')

        self.assertErrorResponse(response, HTTPNotFound, "IpBlock Not Found")

    def test_create_fails_for_non_existent_block_for_given_tenant(self):
        block = IpBlockFactory(tenant_id=123)
        ip_address = IpAddressFactory(ip_block_id=block.id)
        self.block_path = "/ipam/tenants/111/ip_blocks"
        response = self.app.post("%s/%s/ip_addresses"
                                 % (self.block_path, block.id),
                                 status='*')

        self.assertErrorResponse(response, HTTPNotFound, "IpBlock Not Found")

    def test_delete_fails_for_non_existent_block_for_given_tenant(self):
        block = IpBlockFactory(tenant_id=123)
        ip_address = IpAddressFactory(ip_block_id=block.id)
        self.block_path = "/ipam/tenants/111/ip_blocks"
        response = self.app.delete("%s/%s/ip_addresses/%s"
                                 % (self.block_path, block.id,
                                    ip_address.address),
                                 status='*')

        self.assertErrorResponse(response, HTTPNotFound, "IpBlock Not Found")


class TestGlobalIpAddressController(IpAddressControllerBase,
                                     BaseTestController):

    def ip_block_factory(self, **kwargs):
        return IpBlockFactory(**kwargs)

    def address_path(self, block):
        return "/ipam/ip_blocks/{0}/ip_addresses".format(block.id)

    def test_show_fails_for_nonexistent_block(self):
        response = self.app.get("/ipam/ip_blocks/NonExistant"
                                "/ip_addresses/%s" % '10.1.1.0', status="*")

        self.assertEqual(response.status, "404 Not Found")
        self.assertTrue("IpBlock Not Found" in response.body)


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

        self.assertItemsEqual(response.json['ip_addresses'],
                              _data([global_ip_1, global_ip_2]))

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

        self.assertEqual(response.json['ip_addresses'],
                         _data([global_ips[2], global_ips[3]]))

    def test_index_for_nonexistent_block(self):
        non_existant_block_id = 12122
        url = "/ipam/ip_blocks/%s/ip_addresses/%s/inside_globals"
        response = self.app.get(url % (non_existant_block_id, "10.1.1.2"),
                                status='*')

        self.assertErrorResponse(response, HTTPNotFound, "IpBlock Not Found")

    def test_index_for_nonexistent_address(self):
        ip_block, = _create_blocks("191.1.1.1/10")
        url = "/ipam/ip_blocks/%s/ip_addresses/%s/inside_globals"
        response = self.app.get(url % (ip_block.id, '10.1.1.2'),
                                status='*')

        self.assertErrorResponse(response, HTTPNotFound, "IpAddress Not Found")

    def test_create(self):
        global_block, local_block = _create_blocks('192.1.1.1/24',
                                                   '10.1.1.1/24')
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
        global_block, local_block = _create_blocks('192.1.1.1/24',
                                                        '10.1.1.1/24')
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

        self.assertErrorResponse(response, HTTPNotFound,
                                     "IpBlock Not Found")

    def test_delete_for_nonexistent_address(self):
        ip_block, = _create_blocks("191.1.1.1/10")
        url = "/ipam/ip_blocks/%s/ip_addresses/%s/inside_globals"
        response = self.app.delete(url % (ip_block.id, '10.1.1.2'),
                                    status='*')

        self.assertErrorResponse(response, HTTPNotFound,
                                     "IpAddress Not Found")


class TestInsideLocalsController(BaseTestController):

    def test_index(self):
        global_block, local_block = _create_blocks("192.1.1.0/24",
                                                   "10.1.1.0/24")
        [global_ip], local_ips = _allocate_ips((global_block, 1),
                                               (local_block, 5))
        global_ip.add_inside_locals(local_ips)

        response = self.app.get("/ipam/ip_blocks/%s/ip_addresses/%s/"
                                "inside_locals"
                                % (global_block.id, global_ip.address))

        self.assertEqual(response.json['ip_addresses'], _data(local_ips))

    def test_index_with_pagination(self):
        global_block, local_block = _create_blocks("192.1.1.0/24",
                                                        "10.1.1.0/24")
        [global_ip], local_ips = _allocate_ips((global_block, 1),
                                                    (local_block, 5))
        global_ip.add_inside_locals(local_ips)

        response = self.app.get("/ipam/ip_blocks/%s/ip_addresses/%s/"
                                "inside_locals?limit=2&marker=%s"
                                % (global_block.id,
                                   global_ip.address,
                                   local_ips[1].id))

        self.assertEqual(response.json['ip_addresses'],
                         _data([local_ips[2], local_ips[3]]))

    def test_index_for_nonexistent_block(self):
        non_existant_block_id = 12122
        url = "/ipam/ip_blocks/%s/ip_addresses/%s/inside_locals"
        response = self.app.get(url % (non_existant_block_id,
                                       "10.1.1.2"),
                                status='*')

        self.assertErrorResponse(response, HTTPNotFound,
                                 "IpBlock Not Found")

    def test_index_for_nonexistent_address(self):
        ip_block, = _create_blocks("191.1.1.1/10")
        url = "/ipam/ip_blocks/%s/ip_addresses/%s/inside_locals"
        response = self.app.get(url % (ip_block.id, '10.1.1.2'),
                                status='*')

        self.assertErrorResponse(response, HTTPNotFound,
                                     "IpAddress Not Found")

    def test_create(self):
        global_block, = _create_blocks("169.1.1.0/28")
        local_block1, = _create_blocks("10.1.1.0/28")
        local_block2, = _create_blocks("10.0.0.0/28")

        url = "/ipam/ip_blocks/%s/ip_addresses/169.1.1.0/inside_locals"
        json_data = [
            {'ip_block_id': local_block1.id, 'ip_address': "10.1.1.2"},
            {'ip_block_id': local_block2.id, 'ip_address': "10.0.0.2"},
        ]
        request_data = {'ip_addresses': json.dumps(json_data)}
        response = self.app.post(url % global_block.id, request_data)

        self.assertEqual(response.status, "200 OK")
        ips = global_block.find_allocated_ip("169.1.1.0").inside_locals()
        inside_locals = [ip.address for ip in ips]

        self.assertEqual(len(inside_locals), 2)
        self.assertTrue("10.1.1.2" in inside_locals)
        self.assertTrue("10.0.0.2" in inside_locals)
        local_ip = IpAddress.find_by(ip_block_id=local_block1.id,
                                     address="10.1.1.2")
        self.assertEqual(local_ip.inside_globals()[0].address, "169.1.1.0")

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
        global_block, local_block = _create_blocks('192.1.1.1/28',
                                                        '10.1.1.1/28')
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

        self.assertErrorResponse(response, HTTPNotFound,
                                     "IpBlock Not Found")

    def test_delete_for_nonexistent_address(self):
        ip_block, = _create_blocks("191.1.1.1/10")
        url = "/ipam/ip_blocks/%s/ip_addresses/%s/inside_locals"
        response = self.app.delete(url % (ip_block.id, '10.1.1.2'),
                                   status='*')

        self.assertErrorResponse(response, HTTPNotFound,
                                 "IpAddress Not Found")


class UnusableIpRangesControllerBase():

    def test_create(self):
        policy = self._policy_factory()

        response = self.app.post_json("%s/%s/unusable_ip_ranges"
                                 % (self.policy_path, policy.id),
                                 {'ip_range': {'offset': '10', 'length': '2'}})

        unusable_range = IpRange.find_by(policy_id=policy.id)
        self.assertEqual(response.status, "201 Created")
        self.assertEqual(response.json, dict(ip_range=_data(unusable_range)))

    def test_create_on_non_existent_policy(self):
        response = self.app.post("%s/10000/unusable_ip_ranges"
                                 % self.policy_path,
                                 {'ip_range': {'offset': '1', 'length': '2'}},
                                  status="*")

        self.assertErrorResponse(response, HTTPNotFound,
                                 "Policy Not Found")

    def test_show(self):
        policy = self._policy_factory()
        ip_range = IpRangeFactory.create(policy_id=policy.id)

        response = self.app.get("%s/%s/unusable_ip_ranges/%s"
                                % (self.policy_path, policy.id, ip_range.id))

        self.assertEqual(response.status_int, 200)
        self.assertEqual(response.json, dict(ip_range=_data(ip_range)))

    def test_show_when_ip_range_does_not_exists(self):
        policy = self._policy_factory()

        response = self.app.get("%s/%s/unusable_ip_ranges/%s"
                                % (self.policy_path, policy.id, 1000000),
                                status="*")

        self.assertErrorResponse(response, HTTPNotFound,
                                 "IpRange Not Found")

    def test_update(self):
        policy = self._policy_factory()
        ip_range = IpRangeFactory.create(offset=10, length=11,
                                         policy_id=policy.id)

        response = self.app.put_json("%s/%s/unusable_ip_ranges/%s"
                                % (self.policy_path, policy.id, ip_range.id),
                                {'ip_range': {'offset': 1111, 'length': 2222}})

        self.assertEqual(response.status_int, 200)
        updated_range = IpRange.find(ip_range.id)
        self.assertEqual(updated_range.offset, 1111)
        self.assertEqual(updated_range.length, 2222)
        self.assertEqual(response.json, dict(ip_range=_data(updated_range)))

    def test_update_ignores_change_in_policy_id(self):
        policy = self._policy_factory()
        ip_range = IpRangeFactory.create(offset=10, length=11,
                                         policy_id=policy.id)
        new_policy_id = utils.guid()
        response = self.app.put_json("%s/%s/unusable_ip_ranges/%s"
                                % (self.policy_path, policy.id, ip_range.id),
                                {'ip_range': {'offset': 1111, 'length': 2222,
                                'policy_id': new_policy_id}})

        self.assertEqual(response.status_int, 200)
        updated_range = IpRange.find(ip_range.id)
        self.assertEqual(updated_range.offset, 1111)
        self.assertEqual(updated_range.policy_id, policy.id)
        self.assertEqual(response.json['ip_range']['policy_id'], policy.id)

    def test_update_when_ip_range_does_not_exists(self):
        policy = self._policy_factory()

        response = self.app.put_json("%s/%s/unusable_ip_ranges/%s"
                                % (self.policy_path, policy.id, "invalid_id"),
                                {'ip_range': {'offset': 1111, 'length': 222}},
                                status="*")

        self.assertErrorResponse(response, HTTPNotFound,
                                  "IpRange Not Found")

    def test_index(self):
        policy = self._policy_factory()
        for i in range(0, 3):
            IpRangeFactory(policy_id=policy.id)

        response = self.app.get("%s/%s/unusable_ip_ranges"
                                 % (self.policy_path, policy.id))

        response_ranges = response.json["ip_ranges"]
        self.assertEqual(len(response_ranges), 3)
        self.assertItemsEqual(response_ranges,
                         _data(policy.unusable_ip_ranges))

    def test_index_with_pagination(self):
        policy = self._policy_factory()
        ip_ranges = [IpRangeFactory(policy_id=policy.id) for i in range(0, 5)]
        ip_ranges = models.sort(ip_ranges)

        response = self.app.get("%s/%s/unusable_ip_ranges?limit=2&marker=%s"
                                 % (self.policy_path, policy.id,
                                    ip_ranges[0].id))

        next_link = response.json["ip_ranges_links"][0]['href']
        expected_next_link = string.replace(response.request.url,
                                        "marker=%s" % ip_ranges[0].id,
                                        "marker=%s" % ip_ranges[2].id)

        response_ranges = response.json["ip_ranges"]
        self.assertEqual(len(response_ranges), 2)
        self.assertItemsEqual(response_ranges, _data(ip_ranges[1:3]))
        self.assertUrlEqual(next_link, expected_next_link)

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

        self.assertErrorResponse(response, HTTPNotFound,
                                 "Policy Not Found")

    def test_index_fails_for_non_existent_policy_for_given_tenant(self):
        policy = PolicyFactory(tenant_id=123)
        ip_range = IpRangeFactory(policy_id=policy.id)
        self.policy_path = "/ipam/tenants/111/policies"
        response = self.app.get("%s/%s/unusable_ip_ranges"
                                 % (self.policy_path, policy.id),
                                 status='*')

        self.assertErrorResponse(response, HTTPNotFound,
                                 "Policy Not Found")

    def test_create_fails_for_non_existent_policy_for_given_tenant(self):
        policy = PolicyFactory(tenant_id=123)
        ip_range = IpRangeFactory(policy_id=policy.id)
        self.policy_path = "/ipam/tenants/111/policies"
        response = self.app.post_json("%s/%s/unusable_ip_ranges"
                                 % (self.policy_path, policy.id),
                                 {'ip_range': {'offset': 1, 'length': 20}},
                                 status='*')

        self.assertErrorResponse(response, HTTPNotFound,
                                 "Policy Not Found")

    def test_update_fails_for_non_existent_policy_for_given_tenant(self):
        policy = PolicyFactory(tenant_id=123)
        ip_range = IpRangeFactory(policy_id=policy.id)
        self.policy_path = "/ipam/tenants/111/policies"
        response = self.app.put("%s/%s/unusable_ip_ranges/%s"
                                 % (self.policy_path, policy.id, ip_range.id),
                                 {'ip_range': {'offset': 1}}, status='*')

        self.assertErrorResponse(response, HTTPNotFound,
                                 "Policy Not Found")

    def test_delete_fails_for_non_existent_policy_for_given_tenant(self):
        policy = PolicyFactory(tenant_id=123)
        ip_range = IpRangeFactory(policy_id=policy.id)
        self.policy_path = "/ipam/tenants/111/policies"
        response = self.app.delete("%s/%s/unusable_ip_ranges/%s"
                                 % (self.policy_path, policy.id, ip_range.id),
                                 status='*')

        self.assertErrorResponse(response, HTTPNotFound,
                                 "Policy Not Found")


class UnusableIpOctetsControllerBase():

    def test_index(self):
        policy = self._policy_factory()
        for i in range(0, 3):
            IpOctetFactory(policy_id=policy.id)

        response = self.app.get("%s/%s/unusable_ip_octets"
                                 % (self.policy_path, policy.id))

        response_octets = response.json["ip_octets"]
        self.assertEqual(len(response_octets), 3)
        self.assertItemsEqual(response_octets,
                         _data(policy.unusable_ip_octets))

    def test_index_with_pagination(self):
        policy = self._policy_factory()
        ip_octets = [IpOctetFactory(policy_id=policy.id) for i in range(0, 5)]
        ip_octets = models.sort(ip_octets)

        response = self.app.get("%s/%s/unusable_ip_octets?limit=2&marker=%s"
                                 % (self.policy_path, policy.id,
                                    ip_octets[0].id))

        next_link = response.json["ip_octets_links"][0]['href']
        expected_next_link = string.replace(response.request.url,
                                        "marker=%s" % ip_octets[0].id,
                                        "marker=%s" % ip_octets[2].id)

        response_octets = response.json["ip_octets"]
        self.assertEqual(len(response_octets), 2)
        self.assertItemsEqual(response_octets, _data(ip_octets[1:3]))
        self.assertUrlEqual(next_link, expected_next_link)

    def test_create(self):
        policy = self._policy_factory()
        response = self.app.post_json("%s/%s/unusable_ip_octets"
                                 % (self.policy_path, policy.id),
                                 {'ip_octet': {'octet': '123'}})

        ip_octet = IpOctet.find_by(policy_id=policy.id)
        self.assertEqual(response.status, "201 Created")
        self.assertEqual(response.json['ip_octet'], _data(ip_octet))

    def test_create_on_non_existent_policy(self):
        response = self.app.post_json("%s/10000/unusable_ip_octets"
                                 % self.policy_path,
                                 {'ip_octet': {'octet': '2'}}, status="*")

        self.assertErrorResponse(response, HTTPNotFound,
                                 "Policy Not Found")

    def test_show(self):
        policy = self._policy_factory()
        ip_octet = IpOctetFactory(policy_id=policy.id)

        response = self.app.get("%s/%s/unusable_ip_octets/%s"
                                 % (self.policy_path, policy.id, ip_octet.id))

        self.assertEqual(response.status_int, 200)
        self.assertEqual(response.json['ip_octet'], _data(ip_octet))

    def test_show_when_ip_octet_does_not_exists(self):
        policy = self._policy_factory()

        response = self.app.get("%s/%s/unusable_ip_octets/%s"
                                % (self.policy_path, policy.id, 1000000),
                                status="*")

        self.assertErrorResponse(response, HTTPNotFound,
                                  "IpOctet Not Found")

    def test_update(self):
        policy = self._policy_factory()
        ip_octet = IpOctetFactory.create(octet=10, policy_id=policy.id)

        response = self.app.put_json("%s/%s/unusable_ip_octets/%s"
                                % (self.policy_path, policy.id, ip_octet.id),
                                {'ip_octet': {'octet': 123}})

        self.assertEqual(response.status_int, 200)
        updated_octet = IpOctet.find(ip_octet.id)
        self.assertEqual(updated_octet.octet, 123)
        self.assertEqual(response.json['ip_octet'], _data(updated_octet))

    def test_update_ignores_change_in_policy_id(self):
        policy = self._policy_factory()
        ip_octet = IpOctetFactory.create(octet=254, policy_id=policy.id)
        new_policy_id = utils.guid()
        response = self.app.put_json("%s/%s/unusable_ip_octets/%s"
                                % (self.policy_path, policy.id, ip_octet.id),
                                {'ip_octet': {'octet': 253,
                                              'policy_id': new_policy_id}})

        self.assertEqual(response.status_int, 200)
        updated_octet = IpOctet.find(ip_octet.id)
        self.assertEqual(updated_octet.octet, 253)
        self.assertEqual(updated_octet.policy_id, policy.id)
        self.assertEqual(response.json['ip_octet']['policy_id'], policy.id)

    def test_update_when_ip_octet_does_not_exists(self):
        policy = self._policy_factory()

        response = self.app.put_json("%s/%s/unusable_ip_octets/%s"
                                 % (self.policy_path, policy.id, "invalid_id"),
                                 {'ip_octet': {'octet': 222}}, status="*")

        self.assertErrorResponse(response, HTTPNotFound,
                                  "IpOctet Not Found")

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

        self.assertErrorResponse(response, HTTPNotFound,
                                 "Policy Not Found")

    def test_index_fails_for_non_existent_policy_for_given_tenant(self):
        policy = PolicyFactory(tenant_id=123)
        ip_octet = IpOctetFactory(policy_id=policy.id)
        self.policy_path = "/ipam/tenants/111/policies"
        response = self.app.get("%s/%s/unusable_ip_octets"
                                 % (self.policy_path, policy.id),
                                 status='*')

        self.assertErrorResponse(response, HTTPNotFound,
                                 "Policy Not Found")

    def test_create_fails_for_non_existent_policy_for_given_tenant(self):
        policy = PolicyFactory(tenant_id=123)
        ip_octet = IpOctetFactory(policy_id=policy.id)
        self.policy_path = "/ipam/tenants/111/policies"
        response = self.app.post_json("%s/%s/unusable_ip_octets"
                                 % (self.policy_path, policy.id),
                                 {'ip_octet': {'octet': 1}},
                                 status='*')

        self.assertErrorResponse(response, HTTPNotFound,
                                 "Policy Not Found")

    def test_update_fails_for_non_existent_policy_for_given_tenant(self):
        policy = PolicyFactory(tenant_id=123)
        ip_octet = IpOctetFactory(policy_id=policy.id)
        self.policy_path = "/ipam/tenants/111/policies"
        response = self.app.put_json("%s/%s/unusable_ip_octets/%s"
                                 % (self.policy_path, policy.id, ip_octet.id),
                                 {'ip_octet': {'octet': 1}}, status='*')

        self.assertErrorResponse(response, HTTPNotFound,
                                 "Policy Not Found")

    def test_delete_fails_for_non_existent_policy_for_given_tenant(self):
        policy = PolicyFactory(tenant_id=123)
        ip_octet = IpOctetFactory(policy_id=policy.id)
        self.policy_path = "/ipam/tenants/111/policies"
        response = self.app.delete("%s/%s/unusable_ip_octets/%s"
                                 % (self.policy_path, policy.id, ip_octet.id),
                                 status='*')

        self.assertErrorResponse(response, HTTPNotFound,
                                 "Policy Not Found")


class TestPoliciesController(BaseTestController):

    def test_create(self):
        response = self.app.post_json("/ipam/policies",
                                {'policy': {'name': "infrastructure"}})

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
        self.assertItemsEqual(response_policies, _data(policies))

    def test_index_with_pagination(self):
        policies = [PolicyFactory() for i in range(0, 5)]
        policies = models.sort(policies)

        response = self.app.get("/ipam/policies?limit=2&marker=%s"
                                % policies[0].id)

        next_link = response.json["policies_links"][0]['href']
        expected_next_link = string.replace(response.request.url,
                                        "marker=%s" % policies[0].id,
                                        "marker=%s" % policies[2].id)

        response_policies = response.json["policies"]
        self.assertEqual(len(response_policies), 2)
        self.assertItemsEqual(response_policies, _data(policies[1:3]))
        self.assertUrlEqual(next_link, expected_next_link)

    def test_show_when_requested_policy_exists(self):
        policy = PolicyFactory(name="DRAC")

        response = self.app.get("/ipam/policies/%s" % policy.id)

        self.assertEqual(response.status, "200 OK")
        self.assertEqual(response.json, dict(policy=_data(policy)))

    def test_show_when_requested_policy_does_not_exist(self):
        response = self.app.get("/ipam/policies/invalid_id", status="*")

        self.assertErrorResponse(response, HTTPNotFound,
                                 "Policy Not Found")

    def test_update(self):
        policy = PolicyFactory(name="DRAC", description='description')

        response = self.app.put_json("/ipam/policies/%s" % policy.id,
                                {'policy': {'name': "Updated Name",
                                 'description': "Updated Des"}})

        self.assertEqual(response.status_int, 200)
        updated_policy = Policy.find(policy.id)
        self.assertEqual(updated_policy.name, "Updated Name")
        self.assertEqual(updated_policy.description, "Updated Des")
        self.assertEqual(response.json, dict(policy=_data(updated_policy)))

    def test_update_fails_for_invalid_policy_id(self):
        response = self.app.put("/ipam/policies/invalid",
                                {'policy': {'name': "Scrap"}}, status="*")

        self.assertErrorResponse(response, HTTPNotFound,
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
        self.assertItemsEqual(response.json["policies"],
                              _data([policy1, policy3]))

    def test_create(self):
        response = self.app.post_json("/ipam/tenants/1111/policies",
                                 {'policy': {'name': "infrastructure"}})

        self.assertTrue(Policy.find_by(tenant_id="1111") is not None)
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
        policy = PolicyFactory(tenant_id="1111")
        response = self.app.get("/ipam/tenants/1111/policies/%s" % policy.id)

        self.assertEqual(response.status, "200 OK")
        self.assertEqual(response.json['policy']['id'], policy.id)

    def test_show_fails_for_nonexistent_tenant(self):
        policy = PolicyFactory(tenant_id="1112")
        response = self.app.get("/ipam/tenants/1111/policies/%s" % policy.id,
                                status="*")

        self.assertErrorResponse(response, HTTPNotFound,
                                 "Policy Not Found")

    def test_update_fails_for_incorrect_tenant_id(self):
        policy = PolicyFactory(tenant_id="111")
        response = self.app.put_json("/ipam/tenants/123/policies/%s"
                                    % policy.id,
                                {'policy': {'name': "Standard"}}, status="*")

        self.assertErrorResponse(response, HTTPNotFound,
                                 "Policy Not Found")

    def test_update(self):
        policy = PolicyFactory(name="blah", tenant_id="123")
        response = self.app.put_json("/ipam/tenants/123/policies/%s"
                                    % policy.id,
                                    {'policy': {'name': "Standard"}})

        self.assertEqual(response.status_int, 200)
        self.assertEqual("Standard", Policy.find(policy.id).name)

    def test_update_cannot_change_tenant_id(self):
        policy = PolicyFactory(name="Infrastructure", tenant_id="123")
        response = self.app.put_json("/ipam/tenants/123/policies/%s"
                                    % policy.id,
                                    {'policy': {'name': "Standard",
                                                'tenant_id': "124"}})

        self.assertEqual(response.status_int, 200)
        updated_policy = Policy.find(policy.id)
        self.assertEqual(updated_policy.name, "Standard")
        self.assertEqual(updated_policy.tenant_id, "123")
        self.assertEqual(response.json['policy']['tenant_id'], "123")

    def test_delete(self):
        policy = PolicyFactory(tenant_id="123")
        response = self.app.delete("/ipam/tenants/123/policies/%s" % policy.id)

        self.assertEqual(response.status_int, 200)
        self.assertTrue(Policy.get(policy.id) is None)

    def test_delete_fails_for_incorrect_tenant_id(self):
        policy = PolicyFactory(tenant_id="123")
        response = self.app.delete("/ipam/tenants/111/policies/%s" % policy.id,
                                   status="*")

        self.assertErrorResponse(response, HTTPNotFound,
                                 "Policy Not Found")


class NetworksControllerBase(object):

    def test_allocate_ip_address(self):
        ip_block = self._ip_block_factory(network_id=1)

        response = self.app.post("{0}/networks/1/interfaces/123/"
                                 "ip_allocations".format(self.network_path))

        ip_address = IpAddress.find_by(ip_block_id=ip_block.id)
        self.assertEqual(response.status_int, 201)
        self.assertEqual([_data(ip_address, with_ip_block=True)],
                         response.json['ip_addresses'])
        self.assertEqual(ip_address.interface_id, "123")

    def test_allocate_ip_address_for_a_interface(self):
        ip_block = self._ip_block_factory(network_id=1)

        response = self.app.post("{0}/networks/1/interfaces/123/"
                                 "ip_allocations".format(self.network_path))

        ip_address = IpAddress.find_by(ip_block_id=ip_block.id,
                                       interface_id=123)
        self.assertEqual(response.status_int, 201)
        self.assertEqual([_data(ip_address, with_ip_block=True)],
                         response.json['ip_addresses'])

    def test_allocate_ip_with_given_address(self):
        ip_block = self._ip_block_factory(network_id=1, cidr="10.0.0.0/24")

        response = self.app.post_json("{0}/networks/1/interfaces/123"
                                 "/ip_allocations".format(self.network_path),
                                 {'network': {'addresses': ['10.0.0.2']}})

        ip_address = IpAddress.find_by(ip_block_id=ip_block.id,
                                       address="10.0.0.2")
        self.assertEqual(response.status_int, 201)
        self.assertEqual([_data(ip_address, with_ip_block=True)],
                         response.json['ip_addresses'])

    def test_allocate_ip_allocates_v6_address_with_given_params(self):
        mac_address = "11:22:33:44:55:66"
        ipv6_generator = MockIpV6Generator("fe::/96")
        ipv6_block = self._ip_block_factory(network_id=1, cidr="fe::/96")
        self.mock.StubOutWithMock(models, "ipv6_address_generator_factory")
        tenant_id = ipv6_block.tenant_id or "456"
        models.ipv6_address_generator_factory("fe::/96",
                                              mac_address=mac_address,
                                              tenant_id=tenant_id).\
                                              AndReturn(ipv6_generator)

        self.mock.ReplayAll()

        response = self.app.post_json("{0}/networks/1/interfaces/123"
                                   "/ip_allocations".format(self.network_path),
                                    {'network': {'mac_address': mac_address,
                                                 'tenant_id': tenant_id}})

        ipv6_address = IpAddress.find_by(ip_block_id=ipv6_block.id)
        self.assertEqual([_data(ipv6_address, with_ip_block=True)],
                         response.json['ip_addresses'])

    def test_deallocate_ips(self):
        ip_block = self._ip_block_factory(network_id=1)
        ip = ip_block.allocate_ip(interface_id=123)

        response = self.app.delete("{0}/networks/1/interfaces/123/"
                                   "ip_allocations".format(self.network_path))

        ip_address = IpAddress.get(ip.id)
        self.assertEqual(response.status_int, 200)
        self.assertTrue(ip_address.marked_for_deallocation)

    def test_deallocate_ip_when_network_does_not_exist(self):
        response = self.app.delete("{0}/networks/1/interfaces/123/"
                                   "ip_allocations".format(self.network_path),
                                   status="*")

        self.assertErrorResponse(response, HTTPNotFound, "Network 1 not found")

    def test_get_allocated_ips(self):
        ipv4_block = self._ip_block_factory(cidr="10.0.0.0/24", network_id=1)
        ipv6_block = self._ip_block_factory(cidr="fe::/96", network_id=1)
        ip_1 = ipv4_block.allocate_ip(interface_id="123")
        ip_2 = ipv4_block.allocate_ip(interface_id="123")
        tenant_id = ipv6_block.tenant_id or "456"
        ip_3 = ipv6_block.allocate_ip(interface_id="123",
                                      mac_address="aa:bb:cc:dd:ee:ff",
                                      tenant_id=tenant_id)

        response = self.app.get("{0}/networks/1/interfaces/123/ip_allocations"\
                                 .format(self.network_path))
        self.assertEqual(response.status_int, 200)
        self.assertItemsEqual(_data([ip_1, ip_2, ip_3], with_ip_block=True),
                              response.json["ip_addresses"])


class TestGlobalNetworksController(BaseTestController,
                             NetworksControllerBase):

    def setUp(self):
        self.network_path = "/ipam"
        super(TestGlobalNetworksController, self).setUp()

    def _ip_block_factory(self, **kwargs):
        return PublicIpBlockFactory(**kwargs)

    def test_allocate_ip_creates_network_if_network_not_found(self):
        response = self.app.post("/ipam/networks/1/interfaces/123/"
                                 "ip_allocations")

        self.assertEqual(response.status_int, 201)
        ip_address_json = response.json['ip_addresses'][0]
        ip_block = IpBlock.find(ip_address_json['ip_block_id'])
        self.assertEqual(ip_block.network_id, '1')
        self.assertEqual(ip_block.cidr, Config.get('default_cidr'))
        self.assertEqual(ip_block.type, 'private')
        self.assertEqual(ip_block.tenant_id, None)


class TestTenantNetworksController(NetworksControllerBase,
                                   BaseTestController):

    def setUp(self):
        self.network_path = "/ipam/tenants/123"
        super(TestTenantNetworksController, self).setUp()

    def _ip_block_factory(self, **kwargs):
        return PrivateIpBlockFactory(tenant_id="123", **kwargs)

    def test_allocate_ip_creates_network_if_network_not_found(self):
        response = self.app.post("/ipam/tenants/123/networks/1"
                                 "/interfaces/123/ip_allocations")

        self.assertEqual(response.status_int, 201)
        ip_address_json = response.json['ip_addresses'][0]
        ip_block = IpBlock.find(ip_address_json['ip_block_id'])
        self.assertEqual(ip_block.network_id, '1')
        self.assertEqual(ip_block.cidr, Config.get('default_cidr'))
        self.assertEqual(ip_block.type, 'private')
        self.assertEqual(ip_block.tenant_id, '123')


def _allocate_ips(*args):
    return [models.sort([ip_block.allocate_ip() for i in range(num_of_ips)])
            for ip_block, num_of_ips in args]


def _create_blocks(*args):
    return [PrivateIpBlockFactory(cidr=cidr) for cidr in args]


def _data(resource, **options):
    if isinstance(resource, models.ModelBase):
        return sanitize(resource.data(**options))
    return [_data(model, **options) for model in resource]
