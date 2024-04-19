from frameworks.FrameworkPageBuilder import FrameworkPageBuilder

class NISTPageBuilder(FrameworkPageBuilder):
    def init(self):
        super().__init__()
        self.template = 'default'