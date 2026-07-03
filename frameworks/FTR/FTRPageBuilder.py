from frameworks.FrameworkPageBuilder import FrameworkPageBuilder

class FTRPageBuilder(FrameworkPageBuilder):
    def init(self):
        super().init()
        self.template = 'default'
        
    