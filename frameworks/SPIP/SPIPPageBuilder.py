from frameworks.FrameworkPageBuilder import FrameworkPageBuilder

class SPIPPageBuilder(FrameworkPageBuilder):
    def init(self):
        super().__init__()
        self.template = 'default'
        
    