from frameworks.FrameworkPageBuilder import FrameworkPageBuilder


class AAILPageBuilder(FrameworkPageBuilder):
    def init(self):
        super().__init__()
        self.template = 'default'
