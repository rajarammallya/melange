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
from melange.common.pagination import AppUrl
from melange.common.pagination import AtomLink
from melange.common.pagination import PaginatedDataView
from melange.common.utils import find
from melange.tests import BaseTest


class TestPaginatedDataView(BaseTest):

    def test_links_data_for_json(self):
        collection = [{'id': "resource1"}, {'id': "resource2"}]
        next_page_marker = "resource2"
        current_page_url = "http://abc.com/resources?limit=2&marker=resource0"
        expected_href = "http://abc.com/resources?limit=2&marker=resource2"

        data = PaginatedDataView('ip_blocks', collection, current_page_url,
                                 next_page_marker).data_for_json()

        self.assertUrlEqual(data['ip_blocks_links'][0]['href'], expected_href)
        self.assertUrlEqual(data['ip_blocks_links'][0]['rel'], "next")

    def test_links_data_for_xml(self):
        collection = [{'id': "resource1"}, {'id': "resource2"}]
        next_page_marker = "resource2"
        current_page_url = "http://abc.com/resources?limit=2&marker=resource0"
        expected_href = "http://abc.com/resources?limit=2&marker=resource2"

        data = PaginatedDataView('ip_blocks', collection, current_page_url,
                                 next_page_marker).data_for_xml()

        actual_link = find(lambda obj: isinstance(obj, AtomLink),
                           data['ip_blocks'])
        self.assertUrlEqual(actual_link.href, expected_href)
        self.assertUrlEqual(actual_link.rel, "next")

    def test_data_without_links(self):
        collection = [{'id': "resource1"}, {'id': "resource2"}]
        next_page_marker = None
        current_page_url = "http://abc.com/resources?limit=2&marker=resource0"

        view = PaginatedDataView('ip_blocks', collection, current_page_url,
                                 next_page_marker)
        self.assertTrue('ip_blocks_links' not in view.data_for_json())
        data_for_xml = find(lambda obj: isinstance(obj, AtomLink),
                           view.data_for_xml()['ip_blocks'])
        self.assertIsNone(data_for_xml)


class TestAppUrl(BaseTest):

    def test_change_query_params_of_url(self):
        app_url = AppUrl("http://blah.com/resource?q1=v1&q2=v2")
        changed_url = app_url.change_query_params(q2="new_value", new_key="v3")

        expected_changed_url = ("http://blah.com/resource?q1=v1&"
                                "q2=new_value&new_key=v3")
        self.assertUrlEqual(str(changed_url), expected_changed_url)
