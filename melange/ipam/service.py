import routes
from melange.common import wsgi


class IpBlockController(wsgi.Controller):
    def index(self, request):
        return "index"

    def version(self,request):
        return "Melange version 0.1"

class API(wsgi.Router):                                                                
    def __init__(self, options):                                                       
        self.options = options                                                         
        mapper = routes.Mapper()                                                       
        controller = IpBlockController()                                             
        mapper.resource("ip_block", "/ipam/ip_blocks", controller=controller)
        mapper.connect("/", controller=controller, action="version")
        super(API, self).__init__(mapper)                     
                                                                                      
def app_factory(global_conf, **local_conf):                                            
    conf = global_conf.copy()                                                          
    conf.update(local_conf)
    return API(conf)
