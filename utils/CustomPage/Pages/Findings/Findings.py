import json
from utils.Config import Config
from utils.CustomPage.CustomObject import CustomObject

class Findings(CustomObject):
    # SHEETS_TO_SKIP = ['Info', 'Appendix']
    
    def __init__(self):
        super().__init__()
        return
    
    def build(self):
        return