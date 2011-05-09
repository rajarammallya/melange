import unittest

from melange.ipam.models import IpBlock
from melange.ipam import models
from melange.db import session

class TestIpBlock(unittest.TestCase):

    def setUp(self):
        pass
    
    def test_create_ip_block(self):
        block = IpBlock()
        block.update({"cidr":"10.0.0.1\8","network_id":10})
        block.save()

        saved_block = session.get_session().query(IpBlock).filter_by(network_id=10).first()
        self.assertEqual(saved_block.cidr, "10.0.0.1\8")
