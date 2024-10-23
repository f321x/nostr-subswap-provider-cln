
plugin_logger = None

def set_plugin_logger(logger):
    global plugin_logger
    plugin_logger = logger

def get_plugin_logger():
    global plugin_logger
    return plugin_logger
