# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2012 OpenStack LLC.
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


class AddressPublisher(object):

    def republish(self):
        with self.queue() as q:
            if not self.queue_not_initialized(q):
                return
            q.purge()
            for address in self.address_iterator():
                q.put(str(address))

    def queue(self):
        pass

    def queue_not_initialized(self, queue):
        return True

    def addresss_iterator():
        pass
