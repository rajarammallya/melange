# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2010 OpenStack LLC.
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

""" Utility methods for working with WSGI servers """

import datetime
import eventlet.wsgi
import json
import logging
import paste.urlmap
import re
import traceback
import webob
import webob.dec
import webob.exc
from xml.dom import minidom

from openstack.common import wsgi as openstack_wsgi

from melange.common import exception
from melange.common import utils


Router = openstack_wsgi.Router
Server = openstack_wsgi.Server
Middleware = openstack_wsgi.Middleware

eventlet.patcher.monkey_patch(all=False, socket=True)

LOG = logging.getLogger('melange.wsgi')


def versioned_urlmap(*args, **kwargs):
    urlmap = paste.urlmap.urlmap_factory(*args, **kwargs)
    return VersionedURLMap(urlmap)


class VersionedURLMap(object):

    def __init__(self, urlmap):
        self.urlmap = urlmap

    def __call__(self, environ, start_response):
        req = Request(environ)

        if req.url_version is None and req.accept_version is not None:
            version = "/v" + req.accept_version
            http_exc = webob.exc.HTTPNotAcceptable(_("version not supported"))
            app = self.urlmap.get(version, Fault(http_exc))
        else:
            app = self.urlmap

        return app(environ, start_response)


class Request(webob.Request):

    def best_match_content_type(self):
        """Determine the most acceptable content-type.

        Based on the query extension then the Accept header.

        """
        parts = self.path.rsplit('.', 1)

        if len(parts) > 1:
            format = parts[1]
            if format in ['json', 'xml']:
                return 'application/{0}'.format(parts[1])

        ctypes = {'application/vnd.openstack.melange+json': "application/json",
                  'application/vnd.openstack.melange+xml': "application/xml",
                  'application/json': "application/json",
                  'application/xml': "application/xml"}
        bm = self.accept.best_match(ctypes.keys())
        return ctypes.get(bm, 'application/json')

    def get_content_type(self):
        allowed_types = ("application/xml", "application/json")
        self.content_type = self.content_type or "application/json"
        type = self.content_type
        if type in allowed_types:
            return type
        LOG.debug("Wrong Content-Type: %s" % type)
        raise webob.exc.HTTPUnsupportedMediaType(
            _("Content type %s not supported") % type)

    @utils.cached_property
    def accept_version(self):
        accept_header = self.headers.get('ACCEPT', "")
        accept_version_re = re.compile(".*?application/vnd.openstack.melange"
                                       "(\+.+?)?;"
                                       "version=(?P<version_no>\d+\.?\d*)")

        match = accept_version_re.search(accept_header)
        return  match.group("version_no") if match else None

    @utils.cached_property
    def url_version(self):
        versioned_url_re = re.compile("/v(?P<version_no>\d+\.?\d*)")
        match = versioned_url_re.search(self.path)
        return match.group("version_no") if match else None


class Result(object):

    def __init__(self, data, status=200):
        self._data = data
        self.status = status

    def data(self, serialization_type):
        if (serialization_type == "application/xml" and
            hasattr(self._data, "data_for_xml")):
            return self._data.data_for_xml()
        if hasattr(self._data, "data_for_json"):
            return self._data.data_for_json()
        return self._data


class Resource(openstack_wsgi.Resource):

    def __init__(self, controller, deserializer, serializer,
                 admin_actions=None, exception_map=None):
        exception_map = exception_map or {}
        self.model_exception_map = self._invert_dict_list(exception_map)
        self.admin_actions = admin_actions or []
        super(Resource, self).__init__(controller, deserializer, serializer)

    @webob.dec.wsgify(RequestClass=Request)
    def __call__(self, request):
        return super(Resource, self).__call__(request)

    def execute_action(self, action, request, **action_args):
        if getattr(self.controller, action, None) is None:
            return Fault(webob.exc.HTTPNotFound())
        try:
            result = super(Resource, self).execute_action(action,
                                                          request,
                                                          **action_args)
            if type(result) is dict:
                result = Result(result)
            return result

        except exception.MelangeError as melange_error:
            LOG.debug(traceback.format_exc())
            httpError = self._get_http_error(melange_error)
            return Fault(httpError(str(melange_error), request=request))
        except webob.exc.HTTPError as http_error:
            LOG.debug(traceback.format_exc())
            return Fault(http_error)
        except Exception as error:
            LOG.exception(error)
            return Fault(webob.exc.HTTPInternalServerError(error.message,
                                                 request=request))

    def _get_http_error(self, error):
        return self.model_exception_map.get(type(error),
                                            webob.exc.HTTPBadRequest)

    def serialize_response(self, action, action_result, request):
        return self.dispatch(self.serializer, action, action_result, request)

    def _invert_dict_list(self, exception_dict):
        """Flattens values of keys and inverts keys and values.

        Example:
        {'x':[1,2,3],'y':[4,5,6]} converted to
        {1:'x',2:'x',3:'x',4:'y',5:'y',6:'y'}

        """
        inverted_dict = {}
        for key, value_list in exception_dict.items():
            for value in value_list:
                inverted_dict[value] = key
        return inverted_dict


class RequestDeserializer(object):

    def __init__(self, deserializer):
        self.deserializer = deserializer

    def default(self, request):
        if not request.body:
            return {}
        return dict(body=self.deserializer.deserialize(request.body,
                                      request.get_content_type()))


class ResponseSerializer(object):

    def __init__(self, serializer):
        self.serializer = serializer

    def default(self, action_result, request):
        if not isinstance(action_result, Result):
            return action_result

        content_type = request.best_match_content_type()
        data = action_result.data(content_type)
        serialized_data = self.serializer.serialize(data, content_type)
        return webob.Response(body=serialized_data,
                              status=action_result.status,
                              content_type=request.best_match_content_type())


class Controller(object):
    """Base controller that creates a Resource with default serializers."""

    exception_map = {}

    def __init__(self, admin_actions=None):
        self.admin_actions = admin_actions or []

    def create_resource(self):
        return Resource(self, RequestDeserializer(Deserializer()),
                        ResponseSerializer(Serializer()),
                        self.admin_actions, self.exception_map)


class Serializer(object):
    """Serializes a dictionary based on request content type."""

    def __init__(self, metadata=None):
        """ Create a serializer based on the given WSGI environment.

        'metadata' is an optional dict mapping MIME types to information
        needed to serialize a dictionary to that type.

        """
        self.metadata = metadata or {}
        self._methods = {
            'application/json': self._to_json,
            'application/xml': self._to_xml}

    def serialize(self, data, content_type):
        """Serialize a dictionary into a string.

        The format of the string will be decided based on the
        Content Type requested in self.environ:
        by Accept: header, or by URL suffix.

        """
        return self._methods.get(content_type, repr)(data)

    def _to_json(self, data):
        def sanitizer(obj):
            if isinstance(obj, datetime.datetime):
                _dtime = obj - datetime.timedelta(microseconds=obj.microsecond)
                return _dtime.isoformat()
            return obj

        return json.dumps(data, default=sanitizer)

    def _to_xml(self, data):
        metadata = self.metadata.get('application/xml', {})
        # We expect data to contain a single key which is the XML root.
        root_key = data.keys()[0]
        doc = minidom.Document()
        node = self._to_xml_node(doc, metadata, root_key, data[root_key])
        return node.toprettyxml(indent='    ')

    def _to_xml_node(self, doc, metadata, nodename, data):
        """Recursive method to convert data members to XML nodes."""

        if hasattr(data, 'to_xml'):
            return data.to_xml()
        result = doc.createElement(nodename)
        if type(data) is list:
            singular = metadata.get('plurals', {}).get(nodename, None)
            if singular is None:
                if nodename.endswith('s'):
                    singular = nodename[:-1]
                else:
                    singular = 'item'
            for item in data:
                node = self._to_xml_node(doc, metadata, singular, item)
                result.appendChild(node)
        elif type(data) is dict:
            attrs = metadata.get('attributes', {}).get(nodename, {})
            for k, v in data.items():
                if k in attrs:
                    result.setAttribute(k, str(v))
                else:
                    node = self._to_xml_node(doc, metadata, k, v)
                    result.appendChild(node)
        else:
            node = doc.createTextNode(str(data))
            result.appendChild(node)
        return result


class Deserializer(object):
    """Deserializes a dictionary based on request accept content type."""

    def __init__(self, metadata=None):
        """Create a deserializer based on the given WSGI environment.

        'metadata' is an optional dict mapping MIME types to information
        needed to serialize a dictionary to that type.

        """
        self.metadata = metadata or {}

    def deserialize(self, datastring, content_type):
        """Deserialize a string to a dictionary.

        The string must be in the format of a supported MIME type.

        """
        return self.get_deserialize_handler(content_type)(datastring)

    def get_deserialize_handler(self, content_type):
        handlers = {
            'application/json': self._from_json,
            'application/xml': self._from_xml,
        }

        try:
            return handlers[content_type]
        except Exception:
            raise webob.exc.InvalidContentType(content_type=content_type)

    def _from_json(self, datastring):
        return json.loads(datastring or "{}")

    def _from_xml(self, datastring):
        xmldata = self.metadata.get('application/xml', {})
        plurals = set(xmldata.get('plurals', {}))
        node = minidom.parseString(datastring).childNodes[0]
        return {node.nodeName: self._from_xml_node(node, plurals)}

    def _from_xml_node(self, node, listnames):
        """Convert a minidom node to a simple Python type.

        listnames is a collection of names of XML nodes whose subnodes should
        be considered list items.

        """
        if len(node.childNodes) == 1 and node.childNodes[0].nodeType == 3:
            return node.childNodes[0].nodeValue
        elif node.nodeName in listnames:
            return [self._from_xml_node(n, listnames) for n in node.childNodes]
        else:
            result = dict()
            for attr in node.attributes.keys():
                result[attr] = node.attributes[attr].nodeValue
            for child in node.childNodes:
                if child.nodeType != node.TEXT_NODE:
                    result[child.nodeName] = self._from_xml_node(child,
                                                                 listnames)
            return result


class Fault(webob.exc.HTTPException):
    """Error codes for API faults."""

    def __init__(self, exception):
        """Create a Fault for the given webob.exc.exception."""

        self.wrapped_exc = exception

    @webob.dec.wsgify(RequestClass=Request)
    def __call__(self, req):
        """Generate a WSGI response based on the exception passed to ctor."""

        # Replace the body with fault details.
        fault_name = self.wrapped_exc.__class__.__name__
        if(fault_name.startswith("HTTP")):
            fault_name = fault_name[4:]
        fault_data = {
            fault_name: {
                'code': self.wrapped_exc.status_int,
                'message': self.wrapped_exc.explanation,
                'detail': self.wrapped_exc.detail,
                }
            }

        # 'code' is an attribute on the fault tag itself
        metadata = {'application/xml': {'attributes': {fault_name: 'code'}}}
        serializer = Serializer(metadata)
        content_type = req.best_match_content_type()
        self.wrapped_exc.body = serializer.serialize(fault_data, content_type)
        self.wrapped_exc.content_type = content_type
        return self.wrapped_exc
