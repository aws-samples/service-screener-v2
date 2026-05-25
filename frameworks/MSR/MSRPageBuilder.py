from frameworks.FrameworkPageBuilder import FrameworkPageBuilder

class MSRPageBuilder(FrameworkPageBuilder):
    def init(self):
        super().init()
        self.template = 'default'
        
    