from frameworks.FrameworkPageBuilder import FrameworkPageBuilder

class NISTPageBuilder(FrameworkPageBuilder):
    def init(self):
        super().init()
        self.template = 'default'