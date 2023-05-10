from frameworks.FrameworkPageBuilder import FrameworkPageBuilder

class FTRPageBuilder(FrameworkPageBuilder):
    def init(self):
        super().__init__()
        self.template = 'default'
        
    