from services.PageBuilder import PageBuilder
from utils.Config import Config, dashboard

class CustomPageBuilder(PageBuilder):
    def customPageInit(self):
        pass
    
    def init(self):
        self.isHome = False
        self.template = 'customPage'
        
        self.js = []
        self.jsLib = []
        self.cssLib = []
        
        self.customPageInit()
    
    def loadData(self, obj):
        self.data = obj
        
    def buildContentSummary_customPage(self):
        pass
    
    def buildContentDetail_customPage(self):
        pass