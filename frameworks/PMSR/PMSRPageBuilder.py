from frameworks.FrameworkPageBuilder import FrameworkPageBuilder

class PMSRPageBuilder(FrameworkPageBuilder):
    def init(self):
        super().__init__()
        self.template = 'default'
        
    