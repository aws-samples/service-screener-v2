import os, importlib
import constants as _C
from utils.Config import Config
from utils.Tools import _pr

class CustomPage():
    Pages = {}
    def __init__(self):
        self.importCustomObject()
        
    def importCustomObject(self):
        folderPath = 'utils/CustomPage/Pages'
        files = os.listdir(folderPath)
        
        if len(self.Pages) > 0:
            return
        
        for file in files:
            if file[-2:] == 'py':
                cname, ext = file.split('.')
                module = 'utils.CustomPage.Pages.' + cname
                sclass = getattr(importlib.import_module(module), cname)
                self.Pages[cname] = sclass()
    
    def trackInfo(self, driver, name, results):
        for cname, pObj in self.Pages.items():
            pObj.recordItem(driver, name, results)
    
    def resetOutput(self, service):
        serv = service.lower()
        prefix = 'CustomPage.'
        for filename in os.listdir(_C.FORK_DIR):
            if filename.startswith(prefix) and service.lower() in filename:
                file_path = os.path.join(_C.FORK_DIR, filename)
                if os.path.isfile(file_path):
                    os.remove(file_path)
                    _pr(f"Deleted: {file_path}")
    
    def writeOutput(self, service):
        ## TODO: save that particular service only
        serv = service.lower()
        for cname, pObj in self.Pages.items():
            s = pObj.printInfo(serv)
            if s == None:
                return
            
            filename = _C.FORK_DIR + '/CustomPage.' + cname + '.' + service + '.json'
            with open(filename, "w") as f:
                f.write(s)