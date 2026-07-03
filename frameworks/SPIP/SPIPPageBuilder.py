from frameworks.FrameworkPageBuilder import FrameworkPageBuilder

class SPIPPageBuilder(FrameworkPageBuilder):
    def init(self):
        super().init()
        self.template = 'default'