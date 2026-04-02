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
        """
        Write CustomPage output for a specific service.
        
        Note: COH (Cost Optimization Hub) is intentionally skipped here to prevent
        duplicate data collection. COH will collect data once during buildPage() 
        after all services are scanned, ensuring single execution per scan.
        """
        # Check if CustomPage processing is disabled
        if Config.get('disable_custom_pages', False):
            return
            
        ## TODO: save that particular service only
        serv = service.lower()
        for cname, classObj in self.Pages.items():
            # Skip COH during writeOutput - it will collect data once during buildPage()
            if cname == 'COH':
                continue
            
            pObj, pbObj = classObj
            s = pObj.printInfo(serv)
            if s == None:
                return
            
            filename = _C.FORK_DIR + '/CustomPage.' + cname + '.' + service + '.json'
            with open(filename, "w") as f:
                f.write(s)
                
    def buildPage(self):
        # Check if CustomPage processing is disabled
        if Config.get('disable_custom_pages', False):
            self.builtData = {}
            return
            
        arr = {}
        prefix = 'CustomPage.'
        for cname, classObj in self.Pages.items():
            # Skip Findings page during buildPage() - it will be built later after Excel generation
            if cname == 'Findings':
                _pr(f"Skipping {cname} page during buildPage() - will be built after Excel generation")
                continue
                
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
            
        # Store the built data for JSON export
        self.builtData = {}
        for cname, classObj in self.Pages.items():
            if cname == 'Findings':
                continue
            pObj, pbObj = classObj
            # Get the built data from the object
            if hasattr(pObj, 'getBuiltData'):
                self.builtData[f'customPage_{cname.lower()}'] = pObj.getBuiltData()
            elif hasattr(pObj, 'data'):
                self.builtData[f'customPage_{cname.lower()}'] = pObj.data
    
    def getCustomPageData(self):
        """Get all custom page data for JSON export"""
        return getattr(self, 'builtData', {})
    
    def buildFindingsPage(self):
        """
        Build Findings page separately after Excel generation.
        This must be called after workItem.xlsx is created.
        """
        if Config.get('disable_custom_pages', False):
            return
            
        if 'Findings' not in self.Pages:
            return
            
        _pr("Building Findings page (after Excel generation)...")
        try:
            pObj, pbObj = self.Pages['Findings']
            pObj.setData({})
            pObj.build()
            pbObj.loadData(pObj)
            pbObj.buildPage()
            _pr("Findings page built successfully")
        except Exception as e:
            from utils.Tools import _warn
            _warn(f"Failed to build Findings page: {e}")