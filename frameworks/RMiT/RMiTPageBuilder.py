from frameworks.FrameworkPageBuilder import FrameworkPageBuilder

class RMiTPageBuilder(FrameworkPageBuilder):
    def init(self):
        super().__init__()
        self.template = 'default'