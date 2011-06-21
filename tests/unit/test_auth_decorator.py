import unittest
from melange.common import wsgi
from webob import Request
from webob.exc import HTTPForbidden
from webtest import TestApp
import routes


class DummyApp(wsgi.Router):

    def __init__(self, options={}):
        mapper = routes.Mapper()
        admin_actions = ['admin_action']
        controller = StubController(admin_actions=admin_actions)
        mapper.resource("resource", "/resources",
                        controller=controller,
                        collection={'unrestricted': 'get',
                                    'admin_action': 'get'})
        super(DummyApp, self).__init__(mapper)


class StubController(wsgi.Controller):

    def admin_action(self, request):
        pass

    def unrestricted(self, request):
        pass


class TestAuthDecorator(unittest.TestCase):

    def test_forbids_tenants_accessing_admin_actions(self):
        app = TestApp(DummyApp())

        response = app.get("/resources/admin_action", status='*',
                           headers={'X-ROLE': "tenant"})
        self.assertEqual(response.status_int, 403)

    def test_authorizes_admins_accessing_admin_actions(self):
        app = TestApp(DummyApp())

        response = app.get("/resources/admin_action", status='*',
                           headers={'X-ROLE': "admin"})
        self.assertEqual(response.status_int, 200)

    def test_authorizes_tenants_accessing_unrestricted_actions(self):
        app = TestApp(DummyApp())

        response = app.get("/resources/unrestricted", status='*',
                           headers={'X-ROLE': "tenant"})
        self.assertEqual(response.status_int, 200)

    def test_authorizes_admins_accessing_unrestricted_actions(self):
        app = TestApp(DummyApp())

        response = app.get("/resources/unrestricted", status='*',
                           headers={'X-ROLE': "admin"})
        self.assertEqual(response.status_int, 200)

    def test_authorizes_accessing_unrestricted_actions_without_role(self):
        app = TestApp(DummyApp())

        response = app.get("/resources/unrestricted", status='*')
        self.assertEqual(response.status_int, 200)

    def test_forbids_accessing_admin_actions_without_role(self):
        app = TestApp(DummyApp())

        response = app.get("/resources/admin_action", status='*')
        self.assertEqual(response.status_int, 403)
