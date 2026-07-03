from frameworks.FrameworkPageBuilder import FrameworkPageBuilder

class SSBPageBuilder(FrameworkPageBuilder):
    def init(self):
        super().init()
        self.template = 'default'
        
    