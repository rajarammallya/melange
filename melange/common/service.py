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
import inspect
import logging
import webob.dec
from webob.exc import HTTPBadRequest, HTTPInternalServerError
from melange.common.wsgi import Request, Response, Serializer
from melange.common.auth import authorize
from melange.common.exception import MelangeError


class Controller(object):
    """
    WSGI app that reads routing information supplied by RoutesMiddleware
    and calls the requested action method upon itself.  All action methods
    must, in addition to their normal parameters, accept a 'req' argument
    which is the incoming webob.Request.  They raise a webob.exc exception,
    or return a dict which will be serialized by requested content type.
    """
    admin_actions = []

    def __init__(self, http_exception_map={}, admin_actions=[]):
        self.model_exception_map = self._invert_dict_list(http_exception_map)
        self.admin_actions = admin_actions

    @webob.dec.wsgify(RequestClass=Request)
    @authorize
    def __call__(self, req):
        """
        Call the method specified in req.environ by RoutesMiddleware.
        """
        arg_dict = req.environ['wsgiorg.routing_args'][1]
        action = arg_dict['action']
        method = getattr(self, action)
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
        try:
            if self._method_doesnt_expect_format_arg(method):
                arg_dict.pop('format', None)
            return method(**arg_dict)

        except MelangeError as e:
            httpError = self._get_http_error(e)
            self.raiseHTTPError(httpError, e.message, arg_dict['request'])
        except Exception as e:
            logging.getLogger('eventlet.wsgi.server').exception(e)
            self.raiseHTTPError(HTTPInternalServerError, e.message,
                                arg_dict['request'])

    def _method_doesnt_expect_format_arg(self, method):
        return not 'format' in inspect.getargspec(method)[0]

    def raiseHTTPError(self, error, error_message, request):
        raise error(error_message, request=request, content_type="text\plain")

    def _get_http_error(self, error):
        return self.model_exception_map.get(type(error), HTTPBadRequest)

    def _serialize(self, data, request):
        """
        Serialize the given dict to the response type requested in request.
        Uses self._serialization_metadata if it exists, which is a dict mapping
        MIME types to information needed to serialize to that type.
        """
        _metadata = getattr(type(self), "_serialization_metadata", {})
        serializer = Serializer(request.environ, _metadata)
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
