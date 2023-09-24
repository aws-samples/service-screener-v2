from frameworks.FrameworkPageBuilder import FrameworkPageBuilder

class PSRPageBuilder(FrameworkPageBuilder):
    def init(self):
        super().__init__()
        self.template = 'default'
        
    