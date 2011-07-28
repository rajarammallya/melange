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

"""
Utility methods for working with WSGI servers
"""
import datetime
import inspect
import json
import logging
import sys
import re
import eventlet.wsgi
import routes.middleware
import webob.dec
import webob.exc
import paste.urlmap
from webob import Response
from xml.dom import minidom
from webob.exc import (HTTPBadRequest, HTTPInternalServerError,
                       HTTPNotFound, HTTPError, HTTPNotAcceptable)

from melange.common.exception import InvalidContentType
from melange.common.exception import MelangeError
from melange.common.utils import cached_property

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
            app = self.urlmap.get(
                version, Fault(HTTPNotAcceptable("version not supported")))
        else:
            app = self.urlmap

        return app(environ, start_response)


class WritableLogger(object):
    """A thin wrapper that responds to `write` and logs."""

    def __init__(self, logger, level=logging.DEBUG):
        self.logger = logger
        self.level = level

    def write(self, msg):
        self.logger.log(self.level, msg.strip("\n"))


def run_server(application, port):
    """Run a WSGI server with the given application."""
    sock = eventlet.listen(('0.0.0.0', port))
    eventlet.wsgi.server(sock, application)


class Request(webob.Request):

    @property
    def deserialized_params(self):
        return Serializer().deserialize(self.body, self.get_content_type())

    def best_match_content_type(self):
        """Determine the most acceptable content-type.

        Based on the query extension then the Accept header.

        """
        parts = self.path.rsplit('.', 1)

        if len(parts) > 1:
            format = parts[1]
            if format in ['json', 'xml']:
                return 'application/{0}'.format(parts[1])

        ctypes = ['application/json', 'application/xml']
        bm = self.accept.best_match(ctypes)
        return bm or 'application/json'

    def get_content_type(self):
        allowed_types = ("application/xml", "application/json")
        self.content_type = self.content_type or "application/json"
        type = self.content_type
        if type in allowed_types:
            return type
        LOG.debug("Wrong Content-Type: %s" % type)
        raise webob.exc.HTTPUnsupportedMediaType(
        "Content type %s not supported" % type)

    @cached_property
    def accept_version(self):
        accept_header = self.headers.get('ACCEPT', "")
        accept_version_re = re.compile(".*?application/vnd.openstack.melange"
                                       "(\+.+?)?;"
                                       "version=(?P<version_no>\d+\.?\d*)")

        match = accept_version_re.search(accept_header)
        return  match.group("version_no") if match else None

    @cached_property
    def url_version(self):
        versioned_url_re = re.compile("/v(?P<version_no>\d+\.?\d*)")
        match = versioned_url_re.search(self.path)
        return match.group("version_no") if match else None


class Server(object):
    """Server class to manage multiple WSGI sockets and applications."""

    def __init__(self, threads=1000):
        self.pool = eventlet.GreenPool(threads)

    def start(self, application, port, host='0.0.0.0', backlog=128):
        """Run a WSGI server with the given application."""
        socket = eventlet.listen((host, port), backlog=backlog)
        self.pool.spawn_n(self._run, application, socket)

    def wait(self):
        """Wait until all servers have completed running."""
        try:
            self.pool.waitall()
        except KeyboardInterrupt:
            eventlet.convenience.StopServe()

    def _run(self, application, socket):
        """Start a WSGI server in a new green thread."""
        logger = logging.getLogger('eventlet.wsgi.server')
        eventlet.wsgi.server(socket, application, custom_pool=self.pool,
                             log=WritableLogger(logger))


class Middleware(object):
    """
    Base WSGI middleware wrapper. These classes require an application to be
    initialized that will be called next.  By default the middleware will
    simply call its wrapped app, or you can override __call__ to customize its
    behavior.
    """

    @classmethod
    def factory(cls, global_config, **local_config):
        """Used for paste app factories in paste.deploy config files.

        Any local configuration (that is, values under the [filter:APPNAME]
        section of the paste config) will be passed into the `__init__` method
        as kwargs.

        A hypothetical configuration would look like:

            [filter:analytics]
            redis_host = 127.0.0.1
            paste.filter_factory = nova.api.analytics:Analytics.factory

        which would result in a call to the `Analytics` class as

            import nova.api.analytics
            analytics.Analytics(app_from_paste, redis_host='127.0.0.1')

        You could of course re-implement the `factory` method in subclasses,
        but using the kwarg passing it shouldn't be necessary.

        """
        def _factory(app):
            return cls(app, **local_config)
        return _factory

    def __init__(self, application, **local_config):
        self.application = application
        self.local_config = local_config

    def process_request(self, req):
        """
        Called on each request.

        If this returns None, the next application down the stack will be
        executed. If it returns a response then that response will be returned
        and execution will stop here.

        """
        return None

    def process_response(self, response):
        """Do whatever you'd like to the response."""
        return response

    @webob.dec.wsgify
    def __call__(self, req):
        response = self.process_request(req)
        if response:
            return response
        response = req.get_response(self.application)
        return self.process_response(response)


class Debug(Middleware):
    """
    Helper class that can be inserted into any WSGI application chain
    to get information about the request and response.
    """

    @webob.dec.wsgify
    def __call__(self, req):
        print ("*" * 40) + " REQUEST ENVIRON"
        for key, value in req.environ.items():
            print key, "=", value
        print
        resp = req.get_response(self.application)

        print ("*" * 40) + " RESPONSE HEADERS"
        for (key, value) in resp.headers.iteritems():
            print key, "=", value
        print

        resp.app_iter = self.print_generator(resp.app_iter)

        return resp

    @staticmethod
    def print_generator(app_iter):
        """
        Iterator that prints the contents of a wrapper string iterator
        when iterated.
        """
        print ("*" * 40) + " BODY"
        for part in app_iter:
            sys.stdout.write(part)
            sys.stdout.flush()
            yield part
        print


class Router(object):
    """
    WSGI middleware that maps incoming requests to WSGI apps.
    """

    def __init__(self, mapper):
        """
        Create a router for the given routes.Mapper.

        Each route in `mapper` must specify a 'controller', which is a
        WSGI app to call.  You'll probably want to specify an 'action' as
        well and have your controller be a service.Controller, who will route
        the request to the action method.

        Examples:
          mapper = routes.Mapper()
          sc = ServerController()

          # Explicit mapping of one route to a controller+action
          mapper.connect(None, "/svrlist", controller=sc, action="list")

          # Actions are all implicitly defined
          mapper.resource("server", "servers", controller=sc)

          # Pointing to an arbitrary WSGI app.  You can specify the
          # {path_info:.*} parameter so the target app can be handed just that
          # section of the URL.
          mapper.connect(None, "/v1.0/{path_info:.*}", controller=BlogApp())
        """
        self.map = mapper
        self._router = routes.middleware.RoutesMiddleware(self._dispatch,
                                                          self.map)

    @webob.dec.wsgify
    def __call__(self, req):

        """
        Route the incoming request to a controller based on self.map.
        If no match, return a 404.
        """
        return self._router

    @staticmethod
    @webob.dec.wsgify
    def _dispatch(req):
        """
        Called by self._router after matching the incoming request to a route
        and putting the information into req.environ.  Either returns 404
        or the routed WSGI app's response.
        """
        match = req.environ['wsgiorg.routing_args'][1]
        if not match:
            return webob.exc.HTTPNotFound()
        app = match['controller']
        return app


class Controller(object):
    """
    WSGI app that reads routing information supplied by RoutesMiddleware
    and calls the requested action method upon itself.  All action methods
    must, in addition to their normal parameters, accept a 'req' argument
    which is the incoming webob.Request.  They raise a webob.exc exception,
    or return a dict which will be serialized by requested content type.
    """
    exception_map = {}
    admin_actions = []

    def __init__(self, admin_actions=[]):
        self.model_exception_map = self._invert_dict_list(self.exception_map)
        self.admin_actions = admin_actions

    @webob.dec.wsgify(RequestClass=Request)
    def __call__(self, req):
        """
        Call the method specified in req.environ by RoutesMiddleware.
        """
        arg_dict = req.environ['wsgiorg.routing_args'][1]
        action = arg_dict['action']
        method = getattr(self, action, None)
        del arg_dict['controller']
        del arg_dict['action']
        arg_dict['request'] = req

        result = self._execute_action(method, arg_dict)

        if type(result) is dict:
            return Response(body=self._serialize(result, req),
                            content_type=req.best_match_content_type())

        if type(result) is tuple and type(result[0]) is dict:
            return Response(body=self._serialize(result[0], req),
                            content_type=req.best_match_content_type(),
                            status=result[1])
        return result

    def _execute_action(self, method, arg_dict):
        if method is None:
            raise HTTPNotFound
        try:
            if self._method_doesnt_expect_format_arg(method):
                arg_dict.pop('format', None)
            return method(**arg_dict)

        except MelangeError as e:
            httpError = self._get_http_error(e)
            return Fault(httpError(e.message, request=arg_dict['request']))
        except HTTPError as e:
            return Fault(e)
        except Exception as e:
            logging.getLogger('eventlet.wsgi.server').exception(e)
            return Fault(HTTPInternalServerError(e.message,
                              request=arg_dict['request']))

    def _method_doesnt_expect_format_arg(self, method):
        return not 'format' in inspect.getargspec(method)[0]

    def _get_http_error(self, error):
        return self.model_exception_map.get(type(error), HTTPBadRequest)

    def _serialize(self, data, request):
        """
        Serialize the given dict to the response type requested in request.
        Uses self._serialization_metadata if it exists, which is a dict mapping
        MIME types to information needed to serialize to that type.
        """
        _metadata = getattr(type(self), "_serialization_metadata", {})
        serializer = Serializer(_metadata)
        return serializer.serialize(data, request.best_match_content_type())

    def _deserialize(self, data, content_type):
        """Deserialize the request body to the specefied content type.

        Uses self._serialization_metadata if it exists, which is a dict mapping
        MIME types to information needed to serialize to that type.

        """
        _metadata = getattr(type(self), '_serialization_metadata', {})
        serializer = Serializer(_metadata)
        return serializer.deserialize(data, content_type)

    def _invert_dict_list(self, exception_dict):
        """
        {'x':[1,2,3],'y':[4,5,6]} converted to
        {1:'x',2:'x',3:'x',4:'y',5:'y',6:'y'}
        """
        inverted_dict = {}
        for key, value_list in exception_dict.items():
            for value in value_list:
                inverted_dict[value] = key
        return inverted_dict


class Serializer(object):
    """
    Serializes a dictionary to a Content Type specified by a WSGI environment.
    """

    def __init__(self, metadata=None):
        """
        Create a serializer based on the given WSGI environment.
        'metadata' is an optional dict mapping MIME types to information
        needed to serialize a dictionary to that type.
        """
        self.metadata = metadata or {}
        self._methods = {
            'application/json': self._to_json,
            'application/xml': self._to_xml}

    def serialize(self, data, content_type):
        """
        Serialize a dictionary into a string.  The format of the string
        will be decided based on the Content Type requested in self.environ:
        by Accept: header, or by URL suffix.
        """
        return self._methods.get(content_type, repr)(data)

    def _to_json(self, data):
        def sanitizer(obj):
            if isinstance(obj, datetime.datetime):
                return obj.isoformat()
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
        else:  # atom
            node = doc.createTextNode(str(data))
            result.appendChild(node)
        return result

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
            raise InvalidContentType(content_type=content_type)

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
    """Error codes for API faults"""

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
                'detail': self.wrapped_exc.detail}}
        # 'code' is an attribute on the fault tag itself
        metadata = {'application/xml': {'attributes': {fault_name: 'code'}}}
        serializer = Serializer(metadata)
        content_type = req.best_match_content_type()
        self.wrapped_exc.body = serializer.serialize(fault_data, content_type)
        self.wrapped_exc.content_type = content_type
        return self.wrapped_exc
