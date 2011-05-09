# See http://code.google.com/p/python-nose/issues/detail?id=373
# The code below enables nosetests to work with i18n _() blocks    
import __builtin__
setattr(__builtin__, '_', lambda x: x)

def setup():
    import os
    import urlparse
    from melange.common import config
    from melange.db import migration
    from melange.db import session
    
    conf_file, conf = config.load_paste_config("melange",
                        {"config_file": os.path.abspath("../../etc/melange.conf.test")},None)
    conn_string = conf["sql_connection"]
    conn_pieces = urlparse.urlparse(conn_string)
    testdb = conn_pieces.path.strip('/')
    if os.path.exists(testdb):
        os.unlink(testdb)

    migration.db_sync(conf)
    session.configure_db(conf)
