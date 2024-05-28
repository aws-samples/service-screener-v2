import os, importlib, json
import constants as _C
from utils.Config import Config
from utils.Tools import _pr

from services.PageBuilder import PageBuilder

class CustomPage(): 
    Pages = {}
    registrar = []
    def __init__(self):
        self.importCustomObject()
    
    def resetPages(self):
        self.Pages = {}
        
    def importCustomObject(self):
        if len(self.Pages) > 0:
            return
        
        folderPath = 'utils/CustomPage/Pages'
        files = os.listdir(folderPath)

        for file in files:
            if file[0:2] == "__":
                continue
            
            cname = file
            module = 'utils.CustomPage.Pages.' + cname + '.' + cname
            sclass = getattr(importlib.import_module(module), cname)
            
            pname = cname + 'PageBuilder'
            pmodule = 'utils.CustomPage.Pages.' + cname + '.' + pname
            pclass = getattr(importlib.import_module(pmodule), pname)
    
            self.Pages[cname] = [sclass(), pclass('CP' + cname, [])]
            self.registrar.append(cname)
    
    def getRegistrar(self):
        return self.registrar
    
    def trackInfo(self, driver, name, results, inventoryInfo):
        for cname, classObj in self.Pages.items():
            pObj, pbObj = classObj
            pObj.recordItem(driver, name, results, inventoryInfo)
    
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
        for cname, classObj in self.Pages.items():
            pObj, pbObj = classObj
            s = pObj.printInfo(serv)
            if s == None:
                return
            
            filename = _C.FORK_DIR + '/CustomPage.' + cname + '.' + service + '.json'
            with open(filename, "w") as f:
                f.write(s)
                
    def buildPage(self):
        arr = {}
        prefix = 'CustomPage.'
        for cname, classObj in self.Pages.items():
            pObj, pbObj = classObj
            arr[cname] = {}
            toMatch = prefix + cname + '.'
            for filename in os.listdir(_C.FORK_DIR):
                if filename.startswith(toMatch):
                    file_path = os.path.join(_C.FORK_DIR, filename)
                    if os.path.isfile(file_path):
                        with open(file_path, 'r') as f:
                            serv = file_path.split('.')[2]
                            info = f.read()
                            arr[cname][serv] = json.loads(info)
                            
            pObj.setData(arr[cname])
            pObj.build()
            
            pbObj.loadData(pObj)
            pbObj.buildPage()