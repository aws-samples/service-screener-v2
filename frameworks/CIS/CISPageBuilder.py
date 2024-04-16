from frameworks.FrameworkPageBuilder import FrameworkPageBuilder

class CISPageBuilder(FrameworkPageBuilder):
    def init(self):
        super().__init__()
        self.template = 'default'