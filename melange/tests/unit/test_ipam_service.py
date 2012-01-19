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

import string
import unittest

import mox
import netaddr
import routes
import webob.exc

from melange import ipv6
from melange import tests
from melange.common import config
from melange.common import exception
from melange.common import utils
from melange.common import wsgi
from melange.ipam import models
from melange.ipam import service
from melange.ipam import views
from melange.tests import unit
from melange.tests.factories import models as factory_models
from melange.tests.unit import mock_generator


class ControllerTestBase(tests.BaseTest):

    def setUp(self):
        super(ControllerTestBase, self).setUp()
        conf, melange_app = config.Config.load_paste_app('melangeapp',
                {"config_file": unit.test_config_path()}, None)
        self.app = unit.TestApp(melange_app)


class DummyApp(wsgi.Router):

    def __init__(self, controller):
        mapper = routes.Mapper()
        mapper.resource("resource", "/resources",
                                controller=controller.create_resource())
        super(DummyApp, self).__init__(mapper)


class TestBaseControllerExceptionMapping(unittest.TestCase):

    class StubController(service.BaseController):
        def index(self, request):
            raise self.exception

    def _assert_mapping(self, exception, http_code):
        self.StubController.exception = exception
        app = unit.TestApp(DummyApp(self.StubController()))

        response = app.get("/resources", status="*")
        self.assertEqual(response.status_int, http_code)

    def test_exception_to_http_code_mapping(self):
        self._assert_mapping(models.InvalidModelError(None), 400)
        self._assert_mapping(models.ModelNotFoundError, 404)
        self._assert_mapping(exception.NoMoreAddressesError, 422)
        self._assert_mapping(models.AddressDoesNotBelongError, 422)
        self._assert_mapping(models.AddressLockedError, 422)
        self._assert_mapping(models.DuplicateAddressError, 409)
        self._assert_mapping(models.ConcurrentAllocationError, 409)
        self._assert_mapping(exception.ParamsMissingError, 400)

    def test_http_excpetions_are_bubbled_up(self):
        self._assert_mapping(webob.exc.HTTPUnprocessableEntity, 422)
        self._assert_mapping(webob.exc.HTTPNotFound, 404)


class AbstractTestAction():

    def controller(self, action):
        class Controller(service.BaseController, action):
            _model = None

        return Controller()

    def setup_action(self, action):
        test_controller = self.controller(action)
        self.mock_model_cls = self.mock.CreateMock(models.ModelBase)
        self.mock_model_cls.__name__ = "Model"
        self.mock_model = self.mock.CreateMock(models.ModelBase())
        test_controller._model = self.mock_model_cls
        self.app = unit.TestApp(DummyApp(test_controller))


class TestDeleteAction(tests.BaseTest, AbstractTestAction):

    def setUp(self):
        super(TestDeleteAction, self).setUp()
        super(TestDeleteAction, self).setup_action(service.DeleteAction)

    def test_delete(self):
        self.mock_model_cls.find_by(id="some_id").AndReturn(self.mock_model)
        self.mock_model.delete()

        self.mock.ReplayAll()

        response = self.app.delete("/resources/some_id")

        self.assertEqual(response.status_int, 200)


class TestShowAction(tests.BaseTest, AbstractTestAction):

    def setUp(self):
        super(TestShowAction, self).setUp()
        super(TestShowAction, self).setup_action(service.ShowAction)

    def test_show(self):
        self.mock_model_cls.find_by(id="some_id").AndReturn(self.mock_model)
        res = {'a': 'b'}
        self.mock_model.data().AndReturn(res)

        self.mock.ReplayAll()

        response = self.app.get("/resources/some_id")

        self.assertEqual(response.status_int, 200)
        self.assertEqual(res, response.json['model'])


class TestIpBlockController(ControllerTestBase):

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
        ip_block1 = factory_models.PrivateIpBlockFactory(cidr="10.0.0.1/24",
                                                         tenant_id='999')
        ip_block2 = factory_models.PrivateIpBlockFactory(cidr="20.0.0.2/24",
                                                         tenant_id='999')
        factory_models.PrivateIpBlockFactory(cidr="30.1.1.1/2",
                                             network_id="blah",
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


class TestSubnetController(ControllerTestBase):

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
                                               network_id="2",
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


class TestIpAddressController(ControllerTestBase):

    def _address_path(self, block):
        return ("/ipam/tenants/{0}/ip_blocks/{1}/"
                "ip_addresses".format(block.tenant_id, block.id))

    def test_create(self):
        block = factory_models.IpBlockFactory(cidr="10.1.1.0/28")

        response = self.app.post_json(self._address_path(block),
                                      {'ip_address': {
                                          'interface_id': "vif_id",
                                          }
                                       })

        self.assertEqual(response.status, "201 Created")
        allocated_address = models.IpAddress.find_by(ip_block_id=block.id)
        self.assertEqual(allocated_address.address, "10.1.1.0")
        self.assertEqual(response.json,
                         dict(ip_address=_data(allocated_address)))

    def test_create_with_given_address(self):
        block = factory_models.IpBlockFactory(cidr="10.1.1.0/28")
        response = self.app.post_json(self._address_path(block),
                                      {'ip_address': {
                                          'address': '10.1.1.2',
                                          'interface_id': "vif_id",
                                          }
                                       })

        self.assertEqual(response.status, "201 Created")
        created_address_id = response.json['ip_address']['id']
        created_ip = models.IpAddress.find(created_address_id)
        self.assertEqual(created_ip.address, "10.1.1.2"),

    def test_create_with_interface(self):
        block = factory_models.IpBlockFactory()

        self.app.post_json(self._address_path(block),
                           {'ip_address': {"interface_id": "1111"}})

        allocated_address = models.IpAddress.find_by(ip_block_id=block.id)
        interface = models.Interface.find(allocated_address.interface_id)
        self.assertEqual(interface.virtual_interface_id, "1111")

    def test_create_given_the_tenant_using_the_ip(self):
        block = factory_models.IpBlockFactory()

        self.app.post_json(self._address_path(block),
                           {'ip_address': {
                               'tenant_id': "RAX",
                               'interface_id': "vif_id",
                               }
                            })

        interface = models.Interface.find_by(vif_id_on_device="vif_id")
        self.assertEqual(interface.tenant_id, "RAX")

    def test_create_defaults_interface_owner_to_block_owner(self):
        block = factory_models.IpBlockFactory()

        self.app.post_json(self._address_path(block),
                           {'ip_address': {
                               'interface_id': "vif_id",
                               }
                            })

        interface = models.Interface.find_by(vif_id_on_device="vif_id")
        self.assertEqual(interface.tenant_id, block.tenant_id)

    def test_create_given_the_device_using_the_ip(self):
        block = factory_models.IpBlockFactory()

        self.app.post_json(self._address_path(block),
                           {'ip_address': {
                               "interface_id": "iface",
                               "used_by_device": "instance_id"}
                            })

        allocated_address = models.IpAddress.find_by(ip_block_id=block.id)
        interface = models.Interface.find(allocated_address.interface_id)
        self.assertEqual(interface.device_id, "instance_id")

    def test_create_ipv6_address_fails_when_mac_address_not_allocated(self):
        block = factory_models.IpBlockFactory(cidr="ff::/64")

        response = self.app.post_json(self._address_path(block),
                                      {'ip_address': {"interface_id": "1111"}},
                                      status="*")

        self.assertErrorResponse(response, webob.exc.HTTPBadRequest,
                                 "Required params are missing: mac_address")

    def test_create_passes_request_params_to_ipv6_allocation_algorithm(self):
        block = factory_models.IpBlockFactory(cidr="ff::/64")

        ipv6_generator = mock_generator.MockIpV6Generator("ff::/64")
        self.mock.StubOutWithMock(ipv6, "address_generator_factory")
        ipv6.address_generator_factory("ff::/64",
                                       mac_address="10-23-56-78-90-01",
                                       used_by_tenant="111").\
                                       AndReturn(ipv6_generator)

        params = {
            'ip_address': {
                "interface_id": "123",
                'mac_address': "10:23:56:78:90:01",
                'tenant_id': "111",
                },
            }

        self.mock.ReplayAll()
        response = self.app.post_json(self._address_path(block), params)

        self.assertEqual(response.status_int, 201)

    def test_create_allocates_mac_address_when_mac_allocation_is_enabled(self):
        factory_models.MacAddressRangeFactory(cidr="BC:AD:CE:0:0:0/40")
        block = factory_models.IpBlockFactory(cidr="10.0.0.0/24")

        response = self.app.post_json(self._address_path(block),
                                      {'ip_address': {
                                          "interface_id": "iface",
                                          "used_by_device": "instance_id"}
                                       })
        ip = models.IpAddress.find(response.json['ip_address']['id'])
        self.assertEqual(ip.mac_address.eui_format,
                         str(netaddr.EUI("BC:AD:CE:0:0:0")))

    def test_create_does_not_allocate_mac_for_existing_interface(self):
        mac_range = factory_models.MacAddressRangeFactory(
            cidr="BC:AD:CE:0:0:0/40")
        block = factory_models.IpBlockFactory(cidr="10.0.0.0/24")
        iface = factory_models.InterfaceFactory(
            vif_id_on_device="iface_id")
        mac_range.allocate_mac(interface_id=iface.id)

        response = self.app.post_json(self._address_path(block),
                                      {'ip_address': {
                                          "interface_id": "iface_id",
                                          "used_by_device": iface.device_id,
                                          "tenant_id": iface.tenant_id,
                                          }
                                       })

        self.assertEqual(models.Interface.count(), 1)
        self.assertEqual(models.MacAddress.count(), 1)
        ip = models.IpAddress.find(response.json['ip_address']['id'])
        self.assertEqual(ip.mac_address.eui_format,
                         str(netaddr.EUI("BC:AD:CE:0:0:0")))

    def test_show(self):
        block = factory_models.IpBlockFactory(cidr='10.1.1.1/30')
        ip = _allocate_ip(block)

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
        ip = _allocate_ip(block)

        response = self.app.delete("{0}/{1}.xml".format(
            self._address_path(block), ip.address))

        self.assertEqual(response.status, "200 OK")
        self.assertIsNotNone(models.IpAddress.find(ip.id))
        self.assertTrue(models.IpAddress.find(ip.id).marked_for_deallocation)

    def test_index(self):
        block = factory_models.IpBlockFactory()
        address1, address2 = models.sort([_allocate_ip(block)
                                            for i in range(2)])

        response = self.app.get(self._address_path(block))

        ip_addresses = response.json["ip_addresses"]
        self.assertEqual(response.status, "200 OK")
        self.assertEqual(len(ip_addresses), 2)
        self.assertEqual(ip_addresses[0]['address'], address1.address)
        self.assertEqual(ip_addresses[1]['address'], address2.address)

    def test_index_with_pagination(self):
        block = factory_models.IpBlockFactory()
        ips = models.sort([_allocate_ip(block) for i in range(5)])

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
        ips = [_allocate_ip(block) for i in range(5)]
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


class TestIpRoutesController(ControllerTestBase):

    def test_index_all_routes_for_an_ip_block(self):
        block = factory_models.IpBlockFactory(tenant_id="tenant_id")
        ip_routes = [factory_models.IpRouteFactory(source_block_id=block.id),
                     factory_models.IpRouteFactory(source_block_id=block.id),
                     factory_models.IpRouteFactory(source_block_id=block.id),
                     factory_models.IpRouteFactory(source_block_id=block.id),
                     factory_models.IpRouteFactory(source_block_id=block.id)]

        ip_routes = models.sort(ip_routes)

        path = "/ipam/tenants/tenant_id/ip_blocks/%s/ip_routes" % block.id
        response = self.app.get("%s?limit=2&marker=%s" % (path,
                                                          ip_routes[1].id))

        next_link = response.json['ip_routes_links'][0]['href']
        response_blocks = response.json['ip_routes']
        expected_next_link = string.replace(response.request.url,
                                            "marker=%s" % ip_routes[1].id,
                                            "marker=%s" % ip_routes[3].id)

        self.assertEqual(response.status, "200 OK")
        self.assertEqual(len(response_blocks), 2)
        self.assertItemsEqual(response_blocks, _data([ip_routes[2],
                                                      ip_routes[3]]))
        self.assertUrlEqual(expected_next_link, next_link)

    def test_index_fails_for_non_existent_block_for_tenant(self):
        block = factory_models.IpBlockFactory(tenant_id="tenant_id")
        path = "/ipam/tenants/bad_tenant_id/ip_blocks/%s/ip_routes" % block.id
        response = self.app.get(path, status="*")

        self.assertErrorResponse(response, webob.exc.HTTPNotFound,
                                 "IpBlock Not Found")

    def test_create(self):
        block = factory_models.IpBlockFactory(cidr="10.1.1.0/28")
        path = "/ipam/tenants/tenant_id/ip_blocks/%s/ip_routes" % block.id
        params = {
            'ip_route': {
                'destination': "10.1.1.1",
                'netmask': "255.255.255.0",
                'gateway': "10.1.1.0",
                }
            }

        response = self.app.post_json(path, params)

        ip_route = models.IpRoute.find_by(source_block_id=block.id)
        self.assertEqual(ip_route.destination, "10.1.1.1")
        self.assertEqual(ip_route.netmask, "255.255.255.0")
        self.assertEqual(ip_route.gateway, "10.1.1.0")

        self.assertEqual(response.status, "201 Created")
        self.assertEqual(response.json['ip_route'], _data(ip_route))

    def test_create_ignores_source_block_id_in_body(self):
        block = factory_models.IpBlockFactory(cidr="10.1.1.0/28")
        path = "/ipam/tenants/tenant_id/ip_blocks/%s/ip_routes" % block.id
        params = {
            'ip_route': {
                'destination': "10.1.1.1",
                'netmask': "255.255.255.0",
                'gateway': "10.1.1.0",
                'source_block_id': "other_block",
                }
            }

        response = self.app.post_json(path, params)

        ip_route = models.IpRoute.find(response.json['ip_route']['id'])
        self.assertEqual(ip_route.source_block_id, block.id)
        self.assertIsNone(models.IpRoute.get_by(source_block_id="other_block"))

    def test_create_fails_for_non_existent_block_for_tenant(self):
        block = factory_models.IpBlockFactory(tenant_id="tenant_id")
        path = "/ipam/tenants/bad_tenant_id/ip_blocks/%s/ip_routes" % block.id
        params = {
            'ip_route': {
                'destination': "10.1.1.1",
                'netmask': "255.255.255.0",
                'gateway': "10.1.1.0",
                }
            }
        response = self.app.post_json(path, params, status="*")

        self.assertErrorResponse(response, webob.exc.HTTPNotFound,
                                 "IpBlock Not Found")

    def test_show(self):
        block = factory_models.IpBlockFactory(tenant_id="tenant_id")
        ip_route = factory_models.IpRouteFactory(source_block_id=block.id)

        path = "/ipam/tenants/tenant_id/ip_blocks/%s/ip_routes/%s"
        response = self.app.get(path % (block.id, ip_route.id))

        self.assertEqual(response.status_int, 200)
        self.assertItemsEqual(response.json['ip_route'], _data(ip_route))

    def test_show_fails_for_non_existent_block_for_given_tenant(self):
        block = factory_models.IpBlockFactory(tenant_id="tenant_id")
        ip_route = factory_models.IpRouteFactory(source_block_id=block.id)

        path = "/ipam/tenants/non_existent_tenant/ip_blocks/%s/ip_routes/%s"
        response = self.app.get(path % (block.id, ip_route.id), status="*")

        self.assertErrorResponse(response, webob.exc.HTTPNotFound,
                                 "IpBlock Not Found")

    def test_show_fails_for_non_existent_ip_route(self):
        block = factory_models.IpBlockFactory(tenant_id="tenant_id")

        path = "/ipam/tenants/tenant_id/ip_blocks/%s/ip_routes/bad_ip_route"
        response = self.app.get(path % block.id, status="*")

        self.assertErrorResponse(response, webob.exc.HTTPNotFound,
                                 "IpRoute Not Found")

    def test_delete(self):
        block = factory_models.IpBlockFactory(tenant_id="tenant_id")
        ip_route = factory_models.IpRouteFactory(source_block_id=block.id)

        path = "/ipam/tenants/tenant_id/ip_blocks/%s/ip_routes/%s"
        response = self.app.delete(path % (block.id, ip_route.id))

        self.assertEqual(response.status_int, 200)
        self.assertIsNone(models.IpRoute.get(ip_route.id))

    def test_delete_fails_for_non_existent_block_for_given_tenant(self):
        block = factory_models.IpBlockFactory(tenant_id="tenant_id")
        ip_route = factory_models.IpRouteFactory(source_block_id=block.id)

        path = "/ipam/tenants/non_existent_tenant/ip_blocks/%s/ip_routes/%s"
        response = self.app.delete(path % (block.id, ip_route.id), status="*")

        self.assertErrorResponse(response, webob.exc.HTTPNotFound,
                                 "IpBlock Not Found")

    def test_delete_fails_for_non_existent_ip_route(self):
        block = factory_models.IpBlockFactory(tenant_id="tenant_id")

        path = "/ipam/tenants/tenant_id/ip_blocks/%s/ip_routes/bad_ip_route"
        response = self.app.delete(path % block.id, status="*")

        self.assertErrorResponse(response, webob.exc.HTTPNotFound,
                                 "IpRoute Not Found")

    def test_update(self):
        block = factory_models.IpBlockFactory(tenant_id="tenant_id")
        ip_route = factory_models.IpRouteFactory(destination="10.1.1.1",
                                                 netmask="255.255.255.0",
                                                 gateway="10.1.1.0",
                                                 source_block_id=block.id)
        params = {
            'ip_route': {
                'destination': "192.1.1.1",
                'netmask': "255.255.0.0",
                'gateway': "192.1.1.0",
                'source_block_id': "some_other_block_id",
                }
            }

        path = "/ipam/tenants/tenant_id/ip_blocks/%s/ip_routes/%s"
        response = self.app.put_json(path % (block.id, ip_route.id), params)

        updated_ip_route = models.IpRoute.find_by(source_block_id=block.id)
        self.assertEqual(updated_ip_route.destination, "192.1.1.1")
        self.assertEqual(updated_ip_route.netmask, "255.255.0.0")
        self.assertEqual(updated_ip_route.gateway, "192.1.1.0")

        self.assertEqual(response.status_int, 200)
        self.assertEqual(response.json['ip_route'], _data(updated_ip_route))

    def test_update_fails_for_non_existent_block_for_given_tenant(self):
        block = factory_models.IpBlockFactory(tenant_id="tenant_id")
        ip_route = factory_models.IpRouteFactory(source_block_id=block.id)

        path = "/ipam/tenants/non_existent_tenant/ip_blocks/%s/ip_routes/%s"
        response = self.app.put_json(path % (block.id, ip_route.id),
                                     {},
                                     status="*")

        self.assertErrorResponse(response, webob.exc.HTTPNotFound,
                                 "IpBlock Not Found")

    def test_update_fails_for_non_existent_ip_route(self):
        block = factory_models.IpBlockFactory(tenant_id="tenant_id")

        path = "/ipam/tenants/tenant_id/ip_blocks/%s/ip_routes/bad_ip_route"
        response = self.app.delete(path % block.id, {}, status="*")

        self.assertErrorResponse(response, webob.exc.HTTPNotFound,
                                 "IpRoute Not Found")


class TestAllocatedIpAddressController(ControllerTestBase):

    def test_index_returns_allocated_ips_as_paginated_set(self):
        ip_block1 = factory_models.IpBlockFactory(cidr="10.0.0.0/24")
        ip_block2 = factory_models.IpBlockFactory(cidr="20.0.0.0/24")

        block1_ips, block2_ips = _allocate_ips((ip_block1, 3), (ip_block2, 4))

        allocated_ips = models.sort(block1_ips + block2_ips)
        response = self.app.get("/ipam/allocated_ip_addresses.json?"
                                "limit=4&marker=%s" % allocated_ips[1].id)
        self.assertEqual(response.status_int, 200)
        self.assertEqual(len(response.json['ip_addresses']), 4)
        self.assertEqual(response.json['ip_addresses'],
                         _data(allocated_ips[2:6]))

    def test_index_returns_allocated_ips_for_tenant(self):
        block1 = factory_models.IpBlockFactory(cidr="10.0.0.0/24",
                                               tenant_id="1")
        block2 = factory_models.IpBlockFactory(cidr="20.0.0.0/24",
                                               tenant_id="2")
        interface1 = factory_models.InterfaceFactory(tenant_id="tnt1")
        interface2 = factory_models.InterfaceFactory(tenant_id="tnt2")

        tenant1_ip1 = _allocate_ip(block1, interface=interface1)
        tenant1_ip2 = _allocate_ip(block2, interface=interface1)
        tenant2_ip1 = _allocate_ip(block2, interface=interface2)

        response = self.app.get("/ipam/tenants/tnt1/allocated_ip_addresses")

        self.assertItemsEqual(response.json['ip_addresses'],
                              _data([tenant1_ip1, tenant1_ip2]))

    def test_index_returns_allocated_ips_by_device(self):
        block1 = factory_models.IpBlockFactory(cidr="10.0.0.0/24",
                                               tenant_id="1")
        block2 = factory_models.IpBlockFactory(cidr="20.0.0.0/24",
                                               tenant_id="2")

        interface1 = factory_models.InterfaceFactory(device_id="1")
        interface2 = factory_models.InterfaceFactory(device_id="2")

        instance1_ip1 = _allocate_ip(block1, interface=interface1)
        instance1_ip2 = _allocate_ip(block2, interface=interface1)
        instance2_ip1 = _allocate_ip(block2, interface=interface2)

        response = self.app.get("/ipam/allocated_ip_addresses?"
                                "used_by_device=1")

        self.assertItemsEqual(response.json['ip_addresses'],
                              _data([instance1_ip1, instance1_ip2]))

    def test_index_returns_allocated_ips_by_device_for_tenant(self):
        block1 = factory_models.IpBlockFactory(cidr="10.0.0.0/24",
                                               tenant_id="1")
        block2 = factory_models.IpBlockFactory(cidr="20.0.0.0/24",
                                               tenant_id="2")

        interface1 = factory_models.InterfaceFactory(tenant_id="tnt1",
                                                     device_id="device1")
        interface2 = factory_models.InterfaceFactory(tenant_id="tnt1",
                                                     device_id="device2")
        interface3 = factory_models.InterfaceFactory(tenant_id="tnt2",
                                                     device_id="device1")

        tnt1_device1_ip1 = block1.allocate_ip(interface=interface1)
        tnt1_device1_ip2 = block2.allocate_ip(interface=interface1)
        tnt1_device2_ip1 = block1.allocate_ip(interface=interface2)
        tnt2_device1_ip1 = block2.allocate_ip(interface=interface3)

        response = self.app.get("/ipam/tenants/tnt1/allocated_ip_addresses?"
                                "used_by_device=device1")

        self.assertItemsEqual(response.json['ip_addresses'],
                              _data([tnt1_device1_ip1, tnt1_device1_ip2]))

    def test_index_doesnt_return_soft_deallocated_ips(self):
        block = factory_models.IpBlockFactory()
        interface = factory_models.InterfaceFactory(tenant_id="tnt1")

        ip1 = _allocate_ip(block, interface=interface)
        ip2 = _allocate_ip(block, interface=interface)
        ip3 = _allocate_ip(block, interface=interface)

        ip2.deallocate()
        response = self.app.get("/ipam/tenants/tnt1/allocated_ip_addresses")

        self.assertItemsEqual(response.json['ip_addresses'], _data([ip1, ip3]))


class TestInsideGlobalsController(ControllerTestBase):

    def _nat_path(self, block, address):
        return ("/ipam/tenants/{0}/ip_blocks/{1}/ip_addresses/{2}"
                "/inside_globals".format(block.tenant_id,
                                         block.id,
                                         address))

    def test_index(self):
        local_block = factory_models.PrivateIpBlockFactory(cidr="10.1.1.1/30")

        local_ip = _allocate_ip(local_block)
        global_ip1 = factory_models.IpAddressFactory()
        global_ip2 = factory_models.IpAddressFactory()

        local_ip.add_inside_globals([global_ip1, global_ip2])

        response = self.app.get(self._nat_path(local_block, local_ip.address))

        self.assertItemsEqual(response.json['ip_addresses'],
                              _data([global_ip1, global_ip2]))

    def test_index_with_pagination(self):
        local_block = factory_models.PrivateIpBlockFactory(cidr="10.1.1.1/8")
        global_block = factory_models.PublicIpBlockFactory(cidr="192.1.1.1/8")

        [[local_ip]] = _allocate_ips((local_block, 1))
        [global_ips] = _allocate_ips((global_block, 5))
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

        global_ip = _allocate_ip(global_block)
        local_ip = _allocate_ip(local_block)
        response = self.app.post_json(self._nat_path(local_block,
                                                     local_ip.address),
                                      {'ip_addresses': [{
                                          'ip_block_id': global_block.id,
                                          'ip_address': global_ip.address
                                          }]
                                       })

        self.assertEqual(response.status, "200 OK")
        expected_globals = local_ip.inside_globals().all()
        expected_locals = global_ip.inside_locals().all()
        self.assertEqual([global_ip], expected_globals)
        self.assertEqual([local_ip], expected_locals)

    def test_create_throws_error_for_ips_of_other_tenants_blocks(self):
        local_block = factory_models.PublicIpBlockFactory(cidr="77.1.1.0/28")
        other_tenant_global_block = factory_models.PrivateIpBlockFactory(
            cidr="10.1.1.0/28", tenant_id="other_tenant_id")

        local_ip = _allocate_ip(local_block)
        global_ip = _allocate_ip(other_tenant_global_block)

        json_data = [{
            'ip_block_id': other_tenant_global_block.id,
             'ip_address': global_ip.address,
            }]
        request_data = {'ip_addresses': json_data}

        response = self.app.post_json(self._nat_path(local_block,
                                                     local_ip.address),
                                      request_data, status="*")

        self.assertEqual(response.status_int, 404)
        self.assertErrorResponse(response, webob.exc.HTTPNotFound,
                                 "IpBlock Not Found")

    def test_create_for_nonexistent_block_raises_not_found_error(self):
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

    def test_create_for_nonexistent_block_for_given_tenant_raises_404(self):
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

        global_ip = _allocate_ip(global_block)
        local_ip = _allocate_ip(local_block)
        local_ip.add_inside_globals([global_ip])

        response = self.app.delete(self._nat_path(local_block,
                                                  local_ip.address))

        self.assertEqual(response.status, "200 OK")
        self.assertEqual(local_ip.inside_globals().all(), [])

    def test_delete_for_specific_address(self):
        local_block = factory_models.PrivateIpBlockFactory(cidr="10.1.1.1/8")
        global_block = factory_models.PublicIpBlockFactory(cidr="192.1.1.1/8")

        global_ips, = _allocate_ips((global_block, 3))
        local_ip = _allocate_ip(local_block)
        local_ip.add_inside_globals(global_ips)

        self.app.delete("%s/%s" % (self._nat_path(local_block,
                                                  local_ip.address),
                                   global_ips[1].address))

        globals_left = local_ip.inside_globals().all()
        self.assertModelsEqual(globals_left, [global_ips[0], global_ips[2]])

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


class TestInsideLocalsController(ControllerTestBase):

    def _nat_path(self, block, address):
        return ("/ipam/tenants/{0}/ip_blocks/{1}/ip_addresses/{2}"
                "/inside_locals".format(block.tenant_id,
                                         block.id,
                                         address))

    def test_index(self):
        local_block = factory_models.PrivateIpBlockFactory(cidr="10.1.1.1/24")
        global_block = factory_models.PublicIpBlockFactory(cidr="77.1.1.1/24")

        [[global_ip]] = _allocate_ips((global_block, 1))
        [local_ips] = _allocate_ips((local_block, 5))
        global_ip.add_inside_locals(local_ips)

        response = self.app.get(self._nat_path(global_block,
                                               global_ip.address))

        self.assertEqual(response.json['ip_addresses'], _data(local_ips))

    def test_index_with_pagination(self):
        local_block = factory_models.PrivateIpBlockFactory(cidr="10.1.1.1/24")
        global_block = factory_models.PublicIpBlockFactory(cidr="77.1.1.1/24")

        [[global_ip]] = _allocate_ips((global_block, 1))
        [local_ips] = _allocate_ips((local_block, 5))
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

        global_ip = _allocate_ip(global_block)
        local_ip1 = _allocate_ip(local_block1)
        local_ip2 = _allocate_ip(local_block2)

        json_data = [
            {'ip_block_id': local_block1.id, 'ip_address': local_ip1.address},
            {'ip_block_id': local_block2.id, 'ip_address': local_ip2.address},
        ]
        request_data = {'ip_addresses': json_data}
        response = self.app.post_json(self._nat_path(global_block,
                                                     global_ip.address),
                                      request_data)

        self.assertEqual(response.status, "200 OK")
        inside_locals = global_ip.inside_locals().all()

        self.assertModelsEqual(inside_locals, [local_ip1, local_ip2])
        [self.assertEqual(local.inside_globals().all(), [global_ip])
         for local in inside_locals]

    def test_create_throws_error_for_ips_of_other_tenants_blocks(self):
        global_block = factory_models.PublicIpBlockFactory(cidr="77.1.1.0/28")
        other_tenant_local_block = factory_models.PrivateIpBlockFactory(
            cidr="10.1.1.0/28", tenant_id="other_tenant_id")

        global_ip = _allocate_ip(global_block)
        local_ip = _allocate_ip(other_tenant_local_block)

        json_data = [{
            'ip_block_id': other_tenant_local_block.id,
             'ip_address': local_ip.address,
            }]
        request_data = {'ip_addresses': json_data}

        response = self.app.post_json(self._nat_path(global_block,
                                                     global_ip.address),
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
        global_ip = _allocate_ip(global_block)
        global_ip.add_inside_locals(local_ips)

        self.app.delete("{0}/{1}".format(self._nat_path(global_block,
                                                        global_ip.address),
                                         local_ips[1].address))

        locals_left = [ip.address for ip in global_ip.inside_locals()]
        self.assertItemsEqual(locals_left,
                              [local_ips[0].address, local_ips[2].address])

    def test_delete(self):
        local_block = factory_models.PrivateIpBlockFactory(cidr="10.1.1.1/24")
        global_block = factory_models.PublicIpBlockFactory(cidr="77.1.1.1/24")

        global_ip = _allocate_ip(global_block)
        local_ip = _allocate_ip(local_block)
        global_ip.add_inside_locals([local_ip])

        response = self.app.delete(self._nat_path(global_block,
                                                  global_ip.address))

        self.assertEqual(response.status, "200 OK")
        self.assertEqual(global_ip.inside_locals().all(), [])

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


class TestUnusableIpRangesController(ControllerTestBase):

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


class TestUnusableIpOctetsController(ControllerTestBase):

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


class TestPoliciesController(ControllerTestBase):

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


class TestNetworksController(ControllerTestBase):

    def test_index_returns_all_ip_blocks_in_network(self):
        factory = factory_models.PrivateIpBlockFactory
        blocks = [factory(tenant_id="tnt_id", network_id="1"),
                  factory(tenant_id="tnt_id", network_id="1")]
        other_tenant_block = factory(tenant_id="other_tnt_id", network_id="1")
        other_networks_block = factory(tenant_id="tnt_id", network_id="22")

        response = self.app.get("/ipam/tenants/tnt_id/networks/1")

        self.assertEqual(response.status_int, 200)
        self.assertItemsEqual(response.json['ip_blocks'], _data(blocks))

    def test_index_raises_404_if_no_ip_blocks_exist_for_network(self):
        factory = factory_models.PrivateIpBlockFactory
        other_tenant_block = factory(tenant_id="other_tnt_id", network_id="1")
        other_networks_block = factory(tenant_id="tnt_id", network_id="22")

        response = self.app.get("/ipam/tenants/tnt_id/networks/1", status="*")

        self.assertErrorResponse(response, webob.exc.HTTPNotFound,
                                 "Network 1 not found")


class TestInterfaceIpAllocationsController(ControllerTestBase):

    def setUp(self):
        super(TestInterfaceIpAllocationsController, self).setUp()

    def test_create(self):
        ip_block = factory_models.PrivateIpBlockFactory(tenant_id="tnt_id",
                                                        network_id="1")

        response = self.app.post("/ipam/tenants/tnt_id/networks/1/"
                                 "interfaces/123/ip_allocations")

        ip_address = models.IpAddress.find_by(ip_block_id=ip_block.id)
        self.assertEqual(response.status_int, 201)
        self.assertEqual(views.IpConfigurationView(ip_address).data(),
                         response.json['ip_addresses'])
        interface = models.Interface.find(ip_address.interface_id)
        self.assertEqual(interface.virtual_interface_id, "123")

    def test_create_makes_network_owner_the_interface_owner_by_default(self):
        network_1_block = factory_models.IpBlockFactory(tenant_id="tnt_id",
                                                        network_id="1")

        path = "/ipam/tenants/tnt_id/networks/1/interfaces/123/ip_allocations"
        response = self.app.post_json(path)

        interface = models.Interface.find_by(vif_id_on_device="123")

        self.assertEqual(response.status_int, 201)
        self.assertEqual(interface.tenant_id, "tnt_id")

    def test_create_with_given_address(self):
        ip_block = factory_models.PrivateIpBlockFactory(tenant_id="tnt_id",
                                                        network_id="1",
                                                        cidr="10.0.0.0/24")

        response = self.app.post_json("/ipam/tenants/tnt_id/networks/1/"
                                      "interfaces/123/ip_allocations",
                                      {'network': {'addresses': ['10.0.0.2']}})

        ip_address = models.IpAddress.find_by(ip_block_id=ip_block.id,
                                              address="10.0.0.2")
        self.assertEqual(response.status_int, 201)
        self.assertEqual(views.IpConfigurationView(ip_address).data(),
                         response.json['ip_addresses'])

    def test_create_with_optional_params(self):
        ip_block = factory_models.PrivateIpBlockFactory(tenant_id="tnt_id",
                                                        network_id="1",
                                                        cidr="10.0.0.0/24")

        body = {
            'network': {
                'tenant_id': "RAX",
                'used_by_device': "instance_id"
                }
            }

        self.app.post_json("/ipam/tenants/tnt_id/networks/1/"
                           "interfaces/123/ip_allocations", body)

        ip_address = models.IpAddress.find_by(ip_block_id=ip_block.id)
        interface = models.Interface.find(ip_address.interface_id)
        self.assertEqual(interface.tenant_id, "RAX")
        self.assertEqual(interface.virtual_interface_id, "123")
        self.assertEqual(interface.device_id, "instance_id")

    def test_create_allocates_a_mac_as_well_when_mac_ranges_exist(self):
        factory_models.MacAddressRangeFactory(cidr="AD:BC:CE:0:0:0/24")
        ip_block = factory_models.PrivateIpBlockFactory(tenant_id="tnt_id",
                                                        network_id="1",
                                                        cidr="10.0.0.0/24")

        self.app.post_json("/ipam/tenants/tnt_id/networks/1/"
                           "interfaces/123/ip_allocations")

        ip_address = models.IpAddress.find_by(ip_block_id=ip_block.id)
        self.assertEqual(ip_address.mac_address.eui_format,
                         "AD-BC-CE-00-00-00")

    def test_create_allocates_v6_address_with_given_params(self):
        mac_address = "11-22-33-44-55-66"
        ipv6_generator = mock_generator.MockIpV6Generator("fe::/96")
        ipv6_block = factory_models.PrivateIpBlockFactory(tenant_id="tnt_id",
                                                          network_id="1",
                                                          cidr="fe::/96")
        self.mock.StubOutWithMock(ipv6, "address_generator_factory")
        ipv6.address_generator_factory("fe::/96",
                                       mac_address=mac_address,
                                       used_by_tenant="tnt_id").\
                                       AndReturn(ipv6_generator)

        self.mock.ReplayAll()

        response = self.app.post_json("/ipam/tenants/tnt_id/networks/1/"
                                      "interfaces/123/ip_allocations",
                                      {'network': {'mac_address': mac_address,
                                                   'tenant_id': "tnt_id",
                                                   },
                                       })

        ipv6_address = models.IpAddress.find_by(ip_block_id=ipv6_block.id)
        self.assertEqual(views.IpConfigurationView(ipv6_address).data(),
                         response.json['ip_addresses'])

    def test_create_when_network_not_found_creates_default_cidr_block(self):
        with unit.StubConfig(default_cidr="10.0.0.0/24"):
            response = self.app.post("/ipam/tenants/tnt_id/networks/1"
                                     "/interfaces/123/ip_allocations")

        self.assertEqual(response.status_int, 201)
        ip_address_json = response.json['ip_addresses'][0]
        created_block = models.IpAddress.find(ip_address_json['id']).ip_block
        self.assertEqual(created_block.network_id, "1")
        self.assertEqual(created_block.cidr, "10.0.0.0/24")
        self.assertEqual(created_block.type, "private")
        self.assertEqual(created_block.tenant_id, "tnt_id")

    def test_bulk_delete(self):
        ip_block = factory_models.PrivateIpBlockFactory(tenant_id="tnt_id",
                                                        network_id="1")

        interface = factory_models.InterfaceFactory(vif_id_on_device="123")
        ip = ip_block.allocate_ip(interface=interface)

        response = self.app.delete("/ipam/tenants/tnt_id/networks/1/"
                                   "interfaces/123/ip_allocations")

        ip_address = models.IpAddress.get(ip.id)
        self.assertEqual(response.status_int, 200)
        self.assertTrue(ip_address.marked_for_deallocation)

    def test_bulk_delete_when_network_does_not_exist(self):
        response = self.app.delete("/ipam/tenants/tnt_id/networks/1/"
                                   "interfaces/123/ip_allocations", status="*")

        self.assertErrorResponse(response, webob.exc.HTTPNotFound,
                                 "Network 1 not found")

    def test_index(self):
        factory = factory_models.PrivateIpBlockFactory
        ipv4_block = factory(cidr="10.0.0.0/8",
                             network_id="1",
                             tenant_id="tnt_id")
        ipv6_block = factory(cidr="fe::/96",
                             network_id="1",
                             tenant_id="tnt_id")
        iface = factory_models.InterfaceFactory(vif_id_on_device="123")
        models.MacAddress.create(interface_id=iface.id,
                                 address="aa:bb:cc:dd:ee:ff")

        ip1 = ipv4_block.allocate_ip(interface=iface)
        ip2 = ipv4_block.allocate_ip(interface=iface)
        ip3 = ipv6_block.allocate_ip(interface=iface)

        response = self.app.get("/ipam/tenants/tnt_id/networks/1/"
                                "interfaces/123/ip_allocations")

        self.assertEqual(response.status_int, 200)
        self.assertItemsEqual(views.IpConfigurationView(ip1, ip2, ip3).data(),
                              response.json["ip_addresses"])


class TestInterfacesController(ControllerTestBase):

    def test_create_interface(self):
        response = self.app.post_json("/ipam/interfaces",
                                      {'interface': {
                                          'id': "virt_iface",
                                          'device_id': "instance",
                                          'tenant_id': "tnt",
                                          }
                                       })

        self.assertEqual(response.status_int, 201)
        created_interface = models.Interface.find_by(
            vif_id_on_device='virt_iface')

        self.assertEqual(created_interface.device_id, 'instance')
        self.assertEqual(created_interface.tenant_id, 'tnt')
        self.assertEqual(response.json['interface']['tenant_id'], "tnt")
        self.assertEqual(response.json['interface']['device_id'], "instance")

    def test_create_with_given_address_in_network_details(self):
        ip_block = factory_models.PrivateIpBlockFactory(tenant_id="tnt_id",
                                                        network_id="net1",
                                                        cidr="10.0.0.0/24")

        self.app.post_json("/ipam/interfaces",
                           {'interface': {
                               'id': "virt_iface",
                               'device_id': "instance",
                               'tenant_id': "tnt_id",
                               'network': {
                                   'id': "net1",
                                   'addresses': ['10.0.0.2'],
                                   },
                               },
                            })

        ip_address = models.IpAddress.find_by(ip_block_id=ip_block.id,
                                              address="10.0.0.2")
        created_interface = models.Interface.find_by(
            vif_id_on_device="virt_iface")
        self.assertEqual(ip_address.interface_id, created_interface.id)

    def test_create_interface_allocates_mac(self):
        factory_models.MacAddressRangeFactory()
        response = self.app.post_json("/ipam/interfaces",
                           {'interface': {
                               'id': "virt_iface",
                               'device_id': "instance",
                               'tenant_id': "tnt",
                               }
                            })

        created_interface = models.Interface.find_by(
            vif_id_on_device='virt_iface')
        allocated_mac = models.MacAddress.get_by(
            interface_id=created_interface.id)
        self.assertIsNotNone(allocated_mac)
        self.assertEqual(response.json['interface']['mac_address'],
                         allocated_mac.eui_format)

    def test_create_interface_allocates_ips_from_network(self):
        block = factory_models.IpBlockFactory(network_id="net1",
                                              tenant_id="tnt1")
        self.app.post_json("/ipam/interfaces",
                           {'interface': {
                               'id': "virt_iface",
                               'device_id': "instance",
                               'tenant_id': "tnt1",
                               'network': {'id': "net1"}
                               }
                            })

        created_interface = models.Interface.find_by(
            vif_id_on_device='virt_iface')

        allocated_ip = models.IpAddress.find_by(ip_block_id=block.id)
        self.assertEquals(allocated_ip.interface_id, created_interface.id)

    def test_create_allocates_v6_address_with_given_params(self):
        mac_address = "11-22-33-44-55-66"
        ipv6_generator = mock_generator.MockIpV6Generator("fe::/96")
        ipv6_block = factory_models.PrivateIpBlockFactory(tenant_id="tnt_id",
                                                          network_id="net1",
                                                          cidr="fe::/96")
        self.mock.StubOutWithMock(ipv6, "address_generator_factory")
        ipv6.address_generator_factory("fe::/96",
                                       mac_address=mac_address,
                                       used_by_tenant="tnt_id").\
                                       AndReturn(ipv6_generator)

        self.mock.ReplayAll()

        self.app.post_json("/ipam/interfaces",
                           {'interface': {
                               'id': "virt_iface",
                               'device_id': "instance",
                               'tenant_id': "tnt_id",
                               'mac_address': mac_address,
                               'network': {
                                   'id': "net1",
                                   },
                               },
                            })

        created_interface = models.Interface.find_by(
            vif_id_on_device='virt_iface')

        ipv6_address = models.IpAddress.find_by(ip_block_id=ipv6_block.id)
        self.assertEquals(ipv6_address.interface_id, created_interface.id)

    def test_create_when_network_not_found_creates_default_cidr_block(self):
        with unit.StubConfig(default_cidr="10.0.0.0/24"):
            self.app.post_json("/ipam/interfaces",
                               {'interface': {
                                   'id': "virt_iface",
                                   'device_id': "instance",
                                   'tenant_id': "tnt_id",
                                   'network': {'id': "net1"},
                                   }
                                })

        interface = models.Interface.find_by(vif_id_on_device='virt_iface')
        created_block = models.IpAddress.find_by(
            interface_id=interface.id).ip_block
        self.assertEqual(created_block.network_id, "net1")
        self.assertEqual(created_block.cidr, "10.0.0.0/24")
        self.assertEqual(created_block.type, "private")
        self.assertEqual(created_block.tenant_id, "tnt_id")

    def test_delete_deallocates_mac_and_ips_too(self):
        ip_block1 = factory_models.PrivateIpBlockFactory(tenant_id="tnt_id",
                                                        network_id="1")
        ip_block2 = factory_models.PrivateIpBlockFactory(tenant_id="tnt_id",
                                                         network_id="1")
        mac_range = factory_models.MacAddressRangeFactory()
        interface = factory_models.InterfaceFactory(vif_id_on_device="123")
        mac = mac_range.allocate_mac(interface_id=interface.id)
        ip1 = ip_block1.allocate_ip(interface=interface)
        ip2 = ip_block2.allocate_ip(interface=interface)

        response = self.app.delete("/ipam/interfaces/123")

        self.assertEqual(response.status_int, 200)
        self.assertTrue(models.IpAddress.get(ip1.id).marked_for_deallocation)
        self.assertTrue(models.IpAddress.get(ip2.id).marked_for_deallocation)
        self.assertIsNone(models.MacAddress.get(mac.id))

    def test_show_returns_allocated_ips(self):
        iface = factory_models.InterfaceFactory(tenant_id="tnt_id",
                                                vif_id_on_device="vif_id")
        mac = models.MacAddress.create(address="ab:bc:cd:12:23:34",
                                       interface_id=iface.id)
        ip1 = factory_models.IpAddressFactory(interface_id=iface.id)
        ip2 = factory_models.IpAddressFactory(interface_id=iface.id)
        noise_ip = factory_models.IpAddressFactory()

        response = self.app.get("/ipam/tenants/tnt_id/interfaces/vif_id")

        self.assertEqual(response.status_int, 200)
        iface_data = response.json["interface"]
        self.assertEqual(iface_data['id'], iface.virtual_interface_id)
        self.assertEqual(iface_data['mac_address'], mac.eui_format)
        self.assertEqual(len(iface_data['ip_addresses']), 2)
        self.assertEqual(iface_data['ip_addresses'],
                         views.IpConfigurationView(*iface.ip_addresses).data())


class TestInstanceInterfacesController(ControllerTestBase):

    def test_update_creates_interfaces(self):
        net_ids = ["net_id_1", "net_id_2", "net_id_3"]
        for net_id in net_ids:
            factory_models.PrivateIpBlockFactory(tenant_id="RAX",
                                                 network_id=net_id)
        put_data = {'instance': {
            'tenant_id': "tnt",
            'interfaces': [
                {'network': {'id': net_ids[0], 'tenant_id':"RAX"}},
                {'network': {'id': net_ids[1], 'tenant_id':"RAX"}},
                {'network': {'id': net_ids[2], 'tenant_id':"RAX"}},
                ]},
            }

        response = self.app.put_json("/ipam/instances/instance_id/interfaces",
                                     put_data)
        self.assertEqual(response.status_int, 200)
        ifaces = sorted(models.Interface.find_all(device_id='instance_id'),
                        key=lambda iface: iface.plugged_in_network_id())
        self.assertItemsEqual([self._get_iface_data(iface)
                               for iface in ifaces],
                              response.json['instance']['interfaces'])
        for iface, network_id in zip(ifaces, net_ids):
            self.assertEqual('instance_id', iface.device_id)
            self.assertEqual('tnt', iface.tenant_id)
            self.assertEqual(network_id, iface.plugged_in_network_id())

    def test_update_deletes_existing_interface(self):
        provider_block = factory_models.IpBlockFactory(tenant_id="RAX",
                                                       network_id="net_id")
        previous_ip = self._setup_interface_and_ip("instance_id",
                                                   "tenant",
                                                   provider_block)
        put_data = {'instance': {
            'tenant_id': "tenant",
            'interfaces': [{'network': {'id': 'net_id', 'tenant_id':"RAX"}}]}}

        response = self.app.put_json("/ipam/instances/instance_id/interfaces",
                                     put_data)

        self.assertTrue(models.IpAddress.get(
                        previous_ip.id).marked_for_deallocation)

    def test_get_interfaces(self):
        provider_block = factory_models.IpBlockFactory(tenant_id="RAX",
                                                       network_id="net_id")
        self._setup_interface_and_ip("instance_id",
                                     "tenant",
                                     provider_block)

        response = self.app.get("/ipam/instances/instance_id/interfaces")

        iface = models.Interface.find_by(device_id="instance_id")
        self.assertEqual([self._get_iface_data(iface)],
                         response.json['instance']['interfaces'])

    def test_delete_interfaces(self):
        provider_block = factory_models.IpBlockFactory(tenant_id="RAX",
                                                       network_id="net_id")
        self._setup_interface_and_ip("instance_id",
                                     "tenant",
                                     provider_block)
        self._setup_interface_and_ip("instance_id",
                                     "tenant",
                                     provider_block)
        noise_iface = self._setup_interface_and_ip("other_instance",
                                                   "tenant",
                                                   provider_block)

        self.app.delete("/ipam/instances/instance_id/interfaces")

        deleted_instance_ifaces = models.Interface.get_by(
                device_id="instance_id")
        existing_instance_ifaces = models.Interface.get_by(
                device_id="other_instance")

        self.assertIsNone(deleted_instance_ifaces)
        self.assertIsNotNone(existing_instance_ifaces)

    def _get_iface_data(self, iface):
        return unit.sanitize(views.InterfaceConfigurationView(iface).data())

    def _setup_interface_and_ip(self, device_id, tenant_of_device, block):
        iface = factory_models.InterfaceFactory(device_id=device_id,
                                                tenant_id=tenant_of_device)
        return _allocate_ip(block, interface=iface)


class TestMacAddressRangesController(ControllerTestBase):

    def test_create(self):
        params = {'mac_address_range': {'cidr': "ab-bc-cd-12-23-34/40"}}

        response = self.app.post_json("/ipam/mac_address_ranges", params)

        mac_range = models.MacAddressRange.get_by(cidr="ab-bc-cd-12-23-34/40")
        self.assertEqual(response.status_int, 201)
        self.assertIsNotNone(mac_range)
        self.assertEqual(response.json['mac_address_range'],
                         _data(mac_range))

    def test_show(self):
        mac_rng = factory_models.MacAddressRangeFactory(
                cidr="ab-bc-cd-12-23-34/40")
        response = self.app.get("/ipam/mac_address_ranges/%s" % mac_rng.id)

        self.assertEqual(response.json['mac_address_range']['cidr'],
                         "ab-bc-cd-12-23-34/40")

    def test_show_raises_404_for_nonexistent_range(self):
        response = self.app.get("/ipam/mac_address_ranges/non_existent_rng_id",
                                status="*")

        self.assertErrorResponse(response,
                                 webob.exc.HTTPNotFound,
                                 "MacAddressRange Not Found")

    def test_index(self):
        range1 = factory_models.MacAddressRangeFactory()
        range2 = factory_models.MacAddressRangeFactory()

        response = self.app.get("/ipam/mac_address_ranges")

        self.assertItemsEqual(_data([range1, range2]),
                              response.json['mac_address_ranges'])

    def test_delete(self):
        rng = factory_models.MacAddressRangeFactory()

        response = self.app.delete("/ipam/mac_address_ranges/%s" % rng.id)

        self.assertIsNone(models.MacAddressRange.get(rng.id))

    def test_delete_raises_404_for_nonexistent_range(self):
        response = self.app.delete("/ipam/mac_address_ranges/invalid_rng_id",
                                   status="*")

        self.assertErrorResponse(response,
                                 webob.exc.HTTPNotFound,
                                 "MacAddressRange Not Found")


class TestInterfaceAllowedIpsController(ControllerTestBase):

    def test_index(self):
        interface = factory_models.InterfaceFactory(
            tenant_id="tnt_id", vif_id_on_device="vif_id")
        ip_factory = factory_models.IpAddressFactory
        block_factory = factory_models.IpBlockFactory
        ip_on_interface = block_factory(network_id="1").allocate_ip(interface)
        ip1 = ip_factory(ip_block_id=block_factory(network_id="1").id)
        ip2 = ip_factory(ip_block_id=block_factory(network_id="1").id)
        ip3 = ip_factory(ip_block_id=block_factory(network_id="1").id)
        ip4 = ip_factory(ip_block_id=block_factory(network_id="1").id)
        interface.allow_ip(ip1)
        interface.allow_ip(ip2)
        interface.allow_ip(ip3)

        response = self.app.get(
            "/ipam/tenants/tnt_id/interfaces/vif_id/allowed_ips")

        self.assertItemsEqual(response.json['ip_addresses'],
                              _data([ip1, ip2, ip3, ip_on_interface]))

    def test_index_returns_404_when_interface_doesnt_exist(self):
        noise_interface = factory_models.InterfaceFactory(
            tenant_id="tnt_id", vif_id_on_device="vif_id")
        response = self.app.get(
            "/ipam/tenants/tnt_id/interfaces/bad_vif_id/allowed_ips",
            status="*")

        self.assertErrorResponse(response,
                                 webob.exc.HTTPNotFound,
                                 "Interface Not Found")

    def test_index_return_404_when_interface_doesnt_belong_to_tenant(self):
        interface = factory_models.InterfaceFactory(
            tenant_id="tnt_id", vif_id_on_device="vif_id")
        response = self.app.get(
            "/ipam/tenants/bad_tnt_id/interfaces/vif_id/allowed_ips",
            status="*")

        self.assertErrorResponse(response,
                                 webob.exc.HTTPNotFound,
                                 "Interface Not Found")

    def test_create(self):
        interface = factory_models.InterfaceFactory(
            tenant_id="tnt_id", vif_id_on_device="vif_id")
        block = factory_models.IpBlockFactory(network_id="net123")
        ip_on_interface = block.allocate_ip(interface)

        block = factory_models.IpBlockFactory(network_id="net123")
        ip = block.allocate_ip(factory_models.InterfaceFactory(
            tenant_id="tnt_id"))

        response = self.app.post_json(
            ("/ipam/tenants/tnt_id/interfaces/%s/allowed_ips"
             % interface.virtual_interface_id),
            {'allowed_ip': {'network_id': "net123", 'ip_address': ip.address}})

        self.assertEqual(response.status_int, 201)
        self.assertEqual(response.json['ip_address'], _data(ip))

    def test_create_raises_404_when_interface_doesnt_exist(self):
        noise_interface = factory_models.InterfaceFactory(
            tenant_id="tnt_id", vif_id_on_device="vif_id")
        block = factory_models.IpBlockFactory(network_id="net123")
        ip = block.allocate_ip(factory_models.InterfaceFactory(
            tenant_id="tnt_id"))

        response = self.app.post_json(
            "/ipam/tenants/tnt_id/interfaces/bad_iface_id/allowed_ips",
            {'allowed_ip': {'network_id': "net123",
                            'ip_address': ip.address}},
            status="*")

        self.assertErrorResponse(response,
                                 webob.exc.HTTPNotFound,
                                 "Interface Not Found")

    def test_create_raises_404_when_ip_is_not_of_the_same_tenant(self):
        interface = factory_models.InterfaceFactory(
            tenant_id="tnt_id", vif_id_on_device="vif_id")
        block = factory_models.IpBlockFactory(network_id="net123")
        other_tenants_ip = block.allocate_ip(factory_models.InterfaceFactory(
            tenant_id="blah"))

        response = self.app.post_json(
            ("/ipam/tenants/tnt_id/interfaces/%s/allowed_ips"
             % interface.virtual_interface_id),
            {'allowed_ip': {'network_id': "net123",
                            'ip_address': other_tenants_ip.address}},
            status="*")

        err_msg = ("IpAddress with {'used_by_tenant_id': u'tnt_id', "
                   "'address': u'%s'} for network net123 not found"
                   % other_tenants_ip.address)
        self.assertErrorResponse(response, webob.exc.HTTPNotFound, err_msg)

    def test_delete(self):
        interface = factory_models.InterfaceFactory(
            tenant_id="tnt_id", vif_id_on_device="vif_id")
        block = factory_models.IpBlockFactory(network_id="net123")
        ip_on_interface = block.allocate_ip(interface)
        allowed_ip = block.allocate_ip(factory_models.InterfaceFactory())
        interface.allow_ip(allowed_ip)

        self.app.delete("/ipam/tenants/tnt_id/interfaces/vif_id/allowed_ips/%s"
                        % allowed_ip.address)
        self.assertEqual(interface.ips_allowed(), [ip_on_interface])

    def test_delete_fails_for_non_existent_interface(self):
        noise_interface = factory_models.InterfaceFactory(
            tenant_id="tnt_id", vif_id_on_device="vif_id")

        response = self.app.delete("/ipam/tenants/tnt_id/interfaces/"
                                   "bad_iface_id/allowed_ips/10.1.1.1",
                                   status="*")

        self.assertErrorResponse(response,
                                 webob.exc.HTTPNotFound,
                                 "Interface Not Found")

    def test_delete_fails_when_allowed_ip_doesnt_exist(self):
        factory_models.InterfaceFactory(
            tenant_id="tnt_id", vif_id_on_device="vif_id")

        response = self.app.delete("/ipam/tenants/tnt_id/interfaces/"
                                   "vif_id/allowed_ips/10.1.1.1",
                                   status="*")

        self.assertErrorResponse(response,
                                 webob.exc.HTTPNotFound,
                                 "Ip Address 10.1.1.1 hasnt been "
                                 "allowed on interface vif_id")

    def test_show(self):
        interface = factory_models.InterfaceFactory(
            tenant_id="tnt_id", vif_id_on_device="vif_id")
        block = factory_models.IpBlockFactory(network_id="net123")
        ip_on_interface = block.allocate_ip(interface)
        allowed_ip = block.allocate_ip(factory_models.InterfaceFactory())
        interface.allow_ip(allowed_ip)

        response = self.app.get("/ipam/tenants/tnt_id/interfaces/vif_id/"
                                "allowed_ips/%s" % allowed_ip.address)

        self.assertEqual(response.status_int, 200)
        self.assertEqual(response.json['ip_address'], _data(allowed_ip))

    def test_show_raises_404_when_allowed_address_doesnt_exist(self):
        factory_models.InterfaceFactory(
            tenant_id="tnt_id", vif_id_on_device="vif_id")

        response = self.app.get("/ipam/tenants/tnt_id/interfaces/vif_id/"
                                "allowed_ips/10.1.1.1", status="*")

        self.assertErrorResponse(response,
                                 webob.exc.HTTPNotFound,
                                 "Ip Address 10.1.1.1 hasnt been "
                                 "allowed on interface vif_id")

    def test_show_raises_404_when_interface_belongs_to_other_tenant(self):
        factory_models.InterfaceFactory(
            tenant_id="tnt_id", vif_id_on_device="vif_id")

        response = self.app.get("/ipam/tenants/bad_tnt_id/interfaces/vif_id/"
                                "allowed_ips/10.1.1.1", status="*")

        self.assertErrorResponse(response,
                                 webob.exc.HTTPNotFound,
                                 "Interface Not Found")

    def test_show_raises_404_when_interface_doesnt_exist(self):
        factory_models.InterfaceFactory(
            tenant_id="tnt_id", vif_id_on_device="vif_id")

        response = self.app.get("/ipam/tenants/tnt_id/interfaces/bad_vif_id/"
                                "allowed_ips/10.1.1.1", status="*")

        self.assertErrorResponse(response,
                                 webob.exc.HTTPNotFound,
                                 "Interface Not Found")


def _allocate_ips(*args):
    interface = factory_models.InterfaceFactory()
    return [models.sort([_allocate_ip(ip_block, interface=interface)
                         for i in range(num_of_ips)])
            for ip_block, num_of_ips in args]


def _data(resource, **options):
    if isinstance(resource, models.ModelBase):
        return unit.sanitize(resource.data(**options))
    return [_data(model, **options) for model in resource]


def _allocate_ip(block, interface=None, **kwargs):
    if interface is None:
        interface = factory_models.InterfaceFactory()
    return block.allocate_ip(interface=interface, **kwargs)
