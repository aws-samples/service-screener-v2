from frameworks.FrameworkPageBuilder import FrameworkPageBuilder

class WAFOPageBuilder(FrameworkPageBuilder):
    def init(self):
        super().__init__()
        self.template = 'default'
        
    