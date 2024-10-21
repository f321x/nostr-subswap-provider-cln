from pyln.client import Plugin

class CLNPlugin:
    def __init__(self):
        self.plugin = Plugin()
        # register methods in between
        self.plugin.run()

