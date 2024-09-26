from frameworks.FrameworkPageBuilder import FrameworkPageBuilder

class WAFCPageBuilder(FrameworkPageBuilder):
    def init(self):
        super().__init__()
        self.template = 'default'
        
    