from frameworks.FrameworkPageBuilder import FrameworkPageBuilder

class CISPageBuilder(FrameworkPageBuilder):
    def init(self):
        super().init()
        self.template = 'default'