from frameworks.FrameworkPageBuilder import FrameworkPageBuilder

class RMiTPageBuilder(FrameworkPageBuilder):
    def init(self):
        super().init()
        self.template = 'default'