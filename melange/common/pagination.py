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

import urlparse
import urllib

from xml.dom import minidom
from melange.common.wsgi import Result
from melange.common.utils import merge_dicts


class AtomLink(object):
    """An atom link"""

    def __init__(self, rel, href, link_type=None, hreflang=None, title=None):
        self.rel = rel
        self.href = href
        self.link_type = link_type
        self.hreflang = hreflang
        self.title = title

    def to_xml(self):
        ATOM_NAMESPACE = "http://www.w3.org/2005/Atom"
        doc = minidom.Document()
        atom_elem = doc.createElementNS(ATOM_NAMESPACE, "link")
        if self.link_type:
            atom_elem.setAttribute("link_type", self.link_type)
        if self.hreflang:
            atom_elem.setAttribute("hreflang", self.hreflang)
        if self.title:
            atom_elem.setAttribute("title", self.title)
        atom_elem.setAttribute("rel", self.rel)
        atom_elem.setAttribute("href", self.href)
        return atom_elem


class PaginatedResult(Result):

    def __init__(self, paginated_data_view):
        super(PaginatedResult, self).__init__(paginated_data_view)

    def serialize_data(self, serializer, serialization_type):
        data = self.data.data_for_json()
        if serialization_type == "application/xml":
            data = self.data.data_for_xml()
        return serializer.serialize(data, serialization_type)


class PaginatedDataView(object):

    def __init__(self, collection_type, collection, current_page_url,
                 next_page_marker=None):
        self.collection_type = collection_type
        self.collection = collection
        self.current_page_url = current_page_url
        self.next_page_marker = next_page_marker

    def data_for_json(self):
        links_dict = {}
        if self._links():
            links_key = self.collection_type + "_links"
            links_dict[links_key] = self._links()
        return merge_dicts({self.collection_type: self.collection}, links_dict)

    def data_for_xml(self):
        atom_links = [AtomLink(link['rel'], link['href'])
                           for link in self._links()]
        return {self.collection_type: self.collection + atom_links}

    def _create_link(self, marker):
        url = urlparse.urlparse(self.current_page_url)
        query_params = dict(urlparse.parse_qsl(url.query))
        query_params["marker"] = marker
        query_params = urllib.urlencode(query_params)
        return urlparse.ParseResult(url.scheme, url.netloc, url.path,
                           url.params, query_params, url.fragment).geturl()

    def _links(self):
        if not self.next_page_marker:
            return []
        next_link = dict(rel='next',
                         href=self._create_link(self.next_page_marker))
        return [next_link]
