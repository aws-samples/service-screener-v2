from frameworks.FrameworkPageBuilder import FrameworkPageBuilder

class SSBPageBuilder(FrameworkPageBuilder):
    def init(self):
        super().__init__()
        self.template = 'default'
        
    