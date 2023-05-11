from frameworks.FrameworkPageBuilder import FrameworkPageBuilder

class WAFSPageBuilder(FrameworkPageBuilder):
    def init(self):
        super().__init__()
        self.template = 'default'
        
    