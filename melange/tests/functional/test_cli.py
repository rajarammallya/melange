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

import melange
from melange.ipam import models
from melange import tests
from melange.tests.factories import models as factory_models
from melange.tests import functional


def run(command):
    return functional.execute("{0} --port={1} {2} --auth-token=test".format(
        melange.melange_bin_path('melange-client'),
                functional.get_api_port(), command))


class TestIpBlockCLI(tests.BaseTest):

    def test_create_public_block(self):
        policy = factory_models.PolicyFactory()
        exitcode, out, err = run("ip_block create public 10.1.1.0/29 net1 "
                                 "%s" % (policy.id))

        self.assertEqual(exitcode, 0)
        ip_block = models.IpBlock.get_by(cidr="10.1.1.0/29", type='public')
        self.assertTrue(ip_block is not None)
        self.assertEqual(ip_block.network_id, "net1")
        self.assertEqual(ip_block.policy_id, policy.id)
        self.assertEqual(ip_block.tenant_id, None)

    def test_create(self):
        policy = factory_models.PolicyFactory()
        exitcode, out, err = run("ip_block create private 10.1.1.0/29 net1"
                                 " %s" % (policy.id))

        self.assertEqual(exitcode, 0)
        ip_block = models.IpBlock.get_by(cidr="10.1.1.0/29", type='private')
        self.assertTrue(ip_block is not None)
        self.assertEqual(ip_block.network_id, "net1")
        self.assertEqual(ip_block.policy_id, policy.id)
        self.assertEqual(ip_block.tenant_id, None)

    def test_list(self):
        exitcode, out, err = run("ip_block list")

        self.assertEqual(exitcode, 0)
        self.assertIn("ip_blocks", out)

    def test_show(self):
        ip_block = factory_models.PublicIpBlockFactory()

        exitcode, out, err = run("ip_block show %s" % ip_block.id)

        self.assertEqual(exitcode, 0)
        self.assertIn(ip_block.cidr, out)

    def test_update(self):
        ip_block = factory_models.PublicIpBlockFactory()
        policy = factory_models.PolicyFactory()

        exitcode, out, err = run("ip_block update %s new_net %s"
                                 % (ip_block.id, policy.id))

        self.assertEqual(exitcode, 0)
        updated_block = models.IpBlock.find(ip_block.id)
        self.assertEqual(updated_block.network_id, "new_net")
        self.assertEqual(updated_block.policy_id, policy.id)

    def test_delete(self):
        ip_block = factory_models.PublicIpBlockFactory()

        exitcode, out, err = run("ip_block delete %s" % ip_block.id)

        self.assertEqual(exitcode, 0)
        self.assertTrue(models.IpBlock.get(ip_block.id) is None)


class TestTenantBasedIpBlockCLI(tests.BaseTest):

    def test_create(self):
        policy = factory_models.PolicyFactory(tenant_id=123)

        exitcode, out, err = run("ip_block create private 10.1.1.0/29 net1"
                                 " %s -t 123" % policy.id)

        self.assertEqual(exitcode, 0)
        ip_block = models.IpBlock.get_by(cidr="10.1.1.0/29",
                                  type="private", tenant_id="123")
        self.assertTrue(ip_block is not None)
        self.assertEqual(ip_block.network_id, "net1")
        self.assertEqual(ip_block.policy_id, policy.id)

    def test_list(self):
        exitcode, out, err = run("ip_block list -t=123")

        self.assertEqual(exitcode, 0)
        self.assertIn("ip_blocks", out)

    def test_show(self):
        ip_block = factory_models.PrivateIpBlockFactory(tenant_id=123)

        exitcode, out, err = run("ip_block show %s -t 123" % ip_block.id)

        self.assertEqual(exitcode, 0)
        self.assertIn(ip_block.cidr, out)

    def test_update(self):
        ip_block = factory_models.PrivateIpBlockFactory(tenant_id="123")
        policy = factory_models.PolicyFactory()

        exitcode, out, err = run("ip_block update %s new_net %s -t 123"
                                 % (ip_block.id, policy.id))

        self.assertEqual(exitcode, 0)
        updated_block = models.IpBlock.find_by(id=ip_block.id, tenant_id="123")
        self.assertEqual(updated_block.network_id, "new_net")
        self.assertEqual(updated_block.policy_id, policy.id)

    def test_delete(self):
        ip_block = factory_models.PrivateIpBlockFactory(tenant_id=123)

        exitcode, out, err = run("ip_block delete"
                                 " %s -t 123" % ip_block.id)

        self.assertEqual(exitcode, 0)
        self.assertTrue(models.IpBlock.get(ip_block.id) is None)


class TestGlobalSubnetCLI(tests.BaseTest):

    def test_create(self):
        block = factory_models.IpBlockFactory(cidr="10.0.0.0/28")
        exitcode, out, err = run("subnet create {0} 10.0.0.0/29".format(
                                 block.id))

        self.assertEqual(exitcode, 0)
        subnet = models.IpBlock.get_by(parent_id=block.id)
        self.assertTrue(subnet is not None)
        self.assertEqual(subnet.tenant_id, None)

    def test_index(self):
        block = factory_models.IpBlockFactory(cidr="10.0.0.0/28")
        block.subnet("10.0.0.0/30")
        block.subnet("10.0.0.4/30")
        block.subnet("10.0.0.8/30")
        exitcode, out, err = run("subnet list {0}".format(block.id))

        self.assertEqual(exitcode, 0)
        self.assertIn("subnets", out)
        self.assertIn("10.0.0.0/30", out)
        self.assertIn("10.0.0.4/30", out)
        self.assertIn("10.0.0.8/30", out)


class TestTenantBasedSubnetCLI(tests.BaseTest):

    def test_create(self):
        block = factory_models.IpBlockFactory(cidr="10.0.0.0/28",
                                              tenant_id="123")
        exitcode, out, err = run("subnet create {0} 10.0.0.0/29 -t 123".format(
                                 block.id))

        self.assertEqual(exitcode, 0)
        subnet = models.IpBlock.get_by(parent_id=block.id)
        self.assertTrue(subnet is not None)
        self.assertEqual(subnet.tenant_id, "123")

    def test_index(self):
        block = factory_models.IpBlockFactory(cidr="10.0.0.0/28",
                                              tenant_id="123")
        block.subnet("10.0.0.0/30")
        block.subnet("10.0.0.4/30")
        block.subnet("10.0.0.8/30")
        exitcode, out, err = run("subnet list {0} -t 123".format(block.id))

        self.assertEqual(exitcode, 0)
        self.assertIn("subnets", out)
        self.assertIn("10.0.0.0/30", out)
        self.assertIn("10.0.0.4/30", out)
        self.assertIn("10.0.0.8/30", out)


class TestPolicyCLI(tests.BaseTest):

    def _run(self, command):
        return run(command)

    def _policy_factory(self, **kwargs):
        return factory_models.PolicyFactory(**kwargs)

    def test_create(self):
        exitcode, out, err = self._run("policy create policy_name policy_desc")

        self.assertEqual(exitcode, 0)
        policy = models.Policy.get_by(name="policy_name",
                                      description="policy_desc")
        self.assertTrue(policy is not None)
        self.assertEqual(policy.tenant_id, None)

    def test_update(self):
        policy = self._policy_factory(name='name', description='desc')
        exitcode, out, err = self._run("policy update"
                                       " {0} new_name".format(policy.id))

        self.assertEqual(exitcode, 0)
        updated_policy = models.Policy.get(policy.id)
        self.assertEqual(updated_policy.name, "new_name")
        self.assertEqual(updated_policy.description, "desc")

    def test_list(self):
        exitcode, out, err = self._run("policy list")

        self.assertEqual(exitcode, 0)
        self.assertIn("policies", out)

    def test_show(self):
        policy = self._policy_factory(name="blah")

        exitcode, out, err = self._run("policy show %s" % policy.id)

        self.assertEqual(exitcode, 0)
        self.assertIn(policy.name, out)

    def test_delete(self):
        policy = self._policy_factory()
        exitcode, out, err = self._run("policy delete %s" % policy.id)

        self.assertEqual(exitcode, 0)
        self.assertTrue(models.Policy.get(policy.id) is None)


class TestTenantPolicyCLI(TestPolicyCLI):

    def _run(self, command):
        return run(command + " -t 1234")

    def _policy_factory(self, **kwargs):
        return factory_models.PolicyFactory(tenant_id=1234, **kwargs)

    def test_create(self):
        exitcode, out, err = self._run("policy create policy_name policy_desc")

        self.assertEqual(exitcode, 0)
        policy = models.Policy.get_by(name="policy_name",
                                      description="policy_desc")
        self.assertTrue(policy is not None)
        self.assertEqual(policy.tenant_id, "1234")


class TestUnusableIpRangesCLI(tests.BaseTest):

    def _run(self, command):
        return run(command)

    def _policy_factory(self, **kwargs):
        return factory_models.PolicyFactory(**kwargs)

    def test_create(self):
        policy = self._policy_factory()
        exitcode, out, err = self._run("unusable_ip_range create"
                                       " {0} 1 2".format(policy.id))

        self.assertEqual(exitcode, 0)
        ip_range = models.IpRange.get_by(policy_id=policy.id,
                                         offset=1,
                                         length=2)
        self.assertTrue(ip_range is not None)

    def test_update(self):
        policy = self._policy_factory()
        ip_range = factory_models.IpRangeFactory(policy_id=policy.id,
                                                 offset=0,
                                                 length=1)
        exitcode, out, err = self._run("unusable_ip_range update"
                             " {0} {1} 10 122".format(policy.id, ip_range.id))

        updated_ip_range = models.IpRange.find(ip_range.id)

        self.assertEqual(exitcode, 0)
        self.assertEqual(updated_ip_range.offset, 10)
        self.assertEqual(updated_ip_range.length, 122)

    def test_update_with_optional_params(self):
        policy = self._policy_factory()
        ip_range = factory_models.IpRangeFactory(policy_id=policy.id,
                                                 offset=0,
                                                 length=1)
        exitcode, out, err = self._run("unusable_ip_range update"
                                 " {0} {1} 10".format(policy.id, ip_range.id))

        updated_ip_range = models.IpRange.find(ip_range.id)

        self.assertEqual(exitcode, 0)
        self.assertEqual(updated_ip_range.offset, 10)
        self.assertEqual(updated_ip_range.length, 1)

    def test_list(self):
        policy = self._policy_factory()
        exitcode, out, err = self._run("unusable_ip_range list"
                                       " {0}".format(policy.id))

        self.assertEqual(exitcode, 0)
        self.assertIn("ip_ranges", out)

    def test_show(self):
        policy = self._policy_factory()
        ip_range = factory_models.IpRangeFactory(policy_id=policy.id)
        exitcode, out, err = self._run("unusable_ip_range show"
                                    " {0} {1}".format(policy.id, ip_range.id))

        self.assertEqual(exitcode, 0)
        self.assertIn(ip_range.policy_id, out)

    def test_delete(self):
        policy = self._policy_factory()
        ip_range = factory_models.IpRangeFactory(policy_id=policy.id)
        exitcode, out, err = self._run("unusable_ip_range delete"
                                     " {0} {1}".format(policy.id, ip_range.id))

        self.assertEqual(exitcode, 0)
        self.assertTrue(models.IpRange.get(ip_range.id) is None)


class TestTenantUnusableIpRangesCLI(TestUnusableIpRangesCLI):

    def _run(self, command):
        return run(command + " -t 1234")

    def _policy_factory(self, **kwargs):
        return factory_models.PolicyFactory(tenant_id="1234", **kwargs)


class TestUnusableIpOctetsCLI(tests.BaseTest):

    def _run(self, command):
        return run(command)

    def _policy_factory(self, **kwargs):
        return factory_models.PolicyFactory(**kwargs)

    def test_create(self):
        policy = self._policy_factory()
        exitcode, out, err = run("unusable_ip_octet create"
                                 " {0} 255".format(policy.id))

        self.assertEqual(exitcode, 0)
        ip_octet = models.IpOctet.get_by(policy_id=policy.id, octet=255)
        self.assertTrue(ip_octet is not None)

    def test_update(self):
        policy = self._policy_factory()
        ip_octet = factory_models.IpOctetFactory(policy_id=policy.id,
                                                 octet=222)
        exitcode, out, err = run("unusable_ip_octet update"
                                 " {0} {1} 255".format(policy.id, ip_octet.id))

        updated_ip_octet = models.IpOctet.find(ip_octet.id)

        self.assertEqual(exitcode, 0)
        self.assertEqual(updated_ip_octet.octet, 255)

    def test_update_with_optional_params(self):
        policy = self._policy_factory()
        ip_octet = factory_models.IpOctetFactory(policy_id=policy.id,
                                                   octet=222)
        exitcode, out, err = run("unusable_ip_octet update"
                                 " {0} {1}".format(policy.id, ip_octet.id))

        updated_ip_octet = models.IpOctet.find(ip_octet.id)

        self.assertEqual(exitcode, 0)
        self.assertEqual(updated_ip_octet.octet, 222)

    def test_list(self):
        policy = self._policy_factory()
        exitcode, out, err = run("unusable_ip_octet"
                                 " list {0}".format(policy.id))

        self.assertEqual(exitcode, 0)
        self.assertIn("ip_octets", out)

    def test_show(self):
        policy = self._policy_factory()
        ip_octet = factory_models.IpOctetFactory(policy_id=policy.id)
        exitcode, out, err = run("unusable_ip_octet show"
                                 " {0} {1}".format(policy.id, ip_octet.id))

        self.assertEqual(exitcode, 0)
        self.assertIn(ip_octet.policy_id, out)

    def test_delete(self):
        policy = self._policy_factory()
        ip_octet = factory_models.IpOctetFactory(policy_id=policy.id)
        exitcode, out, err = run("unusable_ip_octet delete"
                                 " {0} {1}".format(policy.id, ip_octet.id))

        self.assertEqual(exitcode, 0)
        self.assertTrue(models.IpOctet.get(ip_octet.id) is None)


class TestTenantUnusableIpOctetsCLI(TestUnusableIpRangesCLI):

    def _run(self, command):
        return run(command + " -t 1234")

    def _policy_factory(self, **kwargs):
        return factory_models.PolicyFactory(tenant_id="1234", **kwargs)
