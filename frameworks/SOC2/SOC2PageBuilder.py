from frameworks.FrameworkPageBuilder import FrameworkPageBuilder

class SOC2PageBuilder(FrameworkPageBuilder):
    def init(self):
        super().__init__()
        self.template = 'default'
