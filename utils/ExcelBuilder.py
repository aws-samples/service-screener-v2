import xlsxwriter
from datetime import datetime, date

from utils.Config import Config, dashboard

class ExcelBuilder:
    XLSX_FILENAME = 'adminlte/html/workItem.xlsx'
    XLSX_CREATOR = "Service Screener - AWS Malaysia"
    XLSX_TITLE = "Service Screener WorkList"
    SHEET_TRACKER = []
    SHEET_HEADER = [[
        'Region',
        'Check',
        'Type',
        'ResourceID',
        'Severity',
        'Status'
    ]]
    
    def __init__(self, accountId, ssParams):
        self.obj = xlsxwriter.Workbook(self.XLSX_FILENAME)
        self.accountId = accountId
        self.ssParams = ssParams
        
        self.recommendations = {}
        self.xlsxFormat = {}
        self._setExcelInfo()
        
        self.buildListOfXlsxFormat()
        
        self.InfoSheet = self.obj.add_worksheet('Info')
        self.sheetIndex = 2
        
        
    def buildListOfXlsxFormat(self):
        self.xlsxFormat['bold'] = self.obj.add_format({'bold': True})
        self.xlsxFormat['wrapText'] = self.obj.add_format().set_text_wrap()
        self.xlsxFormat['border'] = self.obj.add_format({'border': 1})
    
    def generateWorkSheet(self, service, raw):
        service = service.upper()
        
        sh = self.obj.add_worksheet(service)

        data = self._formatReporterDataToArray(service, raw)
        
        self.writeRowsInArray(sh, self.SHEET_HEADER, 0, 0)
        self.writeRowsInArray(sh, data, 1, 0)
        
        sh.set_row(0, None, self.xlsxFormat['bold'])
        sh.data_validation('F2:F1048576', self._validation_status())
        self._setAutoSize(sh)
        
        self.sheetIndex += 1
        
    def writeRowsInArray(self, sh, data, startRow, startCol, cFormat=None):
        for _r, _d in enumerate(data):
            sh.write_row(startRow+_r, startCol, _d, cFormat)
        
    def generateRecommendationSheet(self):
        sh = self.obj.add_worksheet('Appendix')
        
        header = [[
            'Service',
            'Check',
            'Short Description',
            'Recommendation'
        ]]
        
        data = []
        for service, det in self.recommendations.items():
            for check, info in det.items():
                data.append([
                    service,
                    check,
                    info[0],
                    self._formatHyperlink(info[1])
                ])
        
        self.writeRowsInArray(sh, header, 0, 0)
        self.writeRowsInArray(sh, data, 1, 0)
        
        sh.set_row(0, None, self.xlsxFormat['bold'])
        sh.set_column("D:D", None, self.xlsxFormat['wrapText'])
        self._setAutoSize(sh)
        
        self.sheetIndex += 1
        
    def buildSummaryPage(self, summary):
        ## <TODO>
        # sh = self.obj.getSheet(0)
        # sh.setTitle("Info")
        sh = self.InfoSheet
        
        info = [
            ['AccountId', "'" + self.accountId],
            ['Generated on', datetime.today().strftime('%Y/%m/%d %H:%M:%S')],
            ['Parameters', self.ssParams]
        ]
        
        ##Append Software Info
        info.append(['...Product Info', '...................'])
        softwareInfo = Config.ADVISOR
        for key, val in softwareInfo.items():
            info.append([key, val])
            
        ##Append number of resources scanned, rules executed and timespent
        info.append(['...Execution Summary', '...................'])
        for key, val in summary.items():
            info.append([key, val])
            
        # sh.fromArray(info, None, 'A1')
        
        self.writeRowsInArray(sh, info, 0, 0)
        
        ## Enhance MAP
        darr = []
        arr = []
        total = 0
        types = dashboard['MAP']
        
        # S, O, C, P, R, Total
        arr.append(['', 'S', 'O', 'C', 'P', 'R', 'Total'])
        darr.append(['', 'S', 'O', 'C', 'P', 'R', '-', 'H', 'M', 'L', 'I', '-', 'Total'])
        for service, v in types.items():
            _ = v['_']
            sum = _['S'] + _['O'] + _['C'] + _['P'] + _['R']
            dsum = v['H'] + v['M'] + v['L'] + v['I']
            arr.append([service, _['S'], _['O'], _['C'], _['P'], _['R'], sum])
            darr.append([service, v['S'], v['O'], v['C'], v['P'], v['R'], '-', v['H'], v['M'], v['L'], v['I'], '-', dsum])
            
        totalServ = len(types)
        endRow = totalServ + 2
        
        sp = endRow + 2
        sp1 = sp+1
        dEndRow = totalServ + sp + 1
        
        # Build HIGH FINDING REPORT
        sh.write('D1', 'Type')
        sh.merge_range('E1:J1', 'High Criticality Findings')
        
        # sh.from_array(arr, None, 'D2', True)
        self.writeRowsInArray(sh, arr, 1, 3, self.xlsxFormat['border'])
        
        # Build DETAIL FINDING REPORT
        sh.write('D' + str(sp), 'Type')
        sh.merge_range("E" + str(sp) + ':' + "P" + str(sp), 'Finding Reports')
        
        self.writeRowsInArray(sh, darr, sp, 3, self.xlsxFormat['border'])
        
        self._setAutoSize(sh)
    
    def _setExcelInfo(self):
        self.obj.set_properties({
            'title': self.XLSX_TITLE,
            'subject': self.XLSX_TITLE,
            'comments': self._getXLSXDescription((self.ssParams)),
            'author': self.XLSX_CREATOR,
            'keywords': 'Screener, AWS, github, Malaysia',
            'created': datetime.now()
        })
    
    def _setAutoSize(self, sh):
        sh.autofit()
            
    def _getXLSXDescription(self, ssParams):
        now = datetime.now()
        return now.strftime('%Y/%m/%d %H:%M:%S') + " | " + ssParams
    
    def _validation_status(self):
        valDict = {
            'validate': 'list',
            'source': ['New', 'Suppressed', 'Resolved'],
            'ignore_blank': False,
            'error_type': 'stop'
        }
        
        return valDict
        
    ## <TODO>
    ## <ACCID><SS><VERS><YYMMDD_His>.xlsx
    def _getFileName(self, folderPath):
        return folderPath + self.XLSX_FILENAME
    
    def _formatReporterDataToArray(self, service, cardSummary):
        arr = []
        for check, detail in cardSummary.items():
            if not detail['__links']:
                detail['__links'] = ''
            
            if not service in self.recommendations:
                self.recommendations[service] = {}
                
            self.recommendations[service][check] = [detail['shortDesc'], detail['__links']]
            for region, resources in detail['__affectedResources'].items():
                for resource in resources:
                    arr.append([
                        region,
                        check,
                        self._getPillarName(detail['__categoryMain']),
                        resource,
                        self._getCriticallyName(detail['criticality']),
                        'New'
                    ])
        return arr
    
    def _save(self, folderPath=''):
        if bool(self.recommendations):
            self.generateRecommendationSheet()
            
        self.obj.close()
        return
    
    def _getPillarName(self, category):
        mapped = {
            'T': 'Text',
            'O': 'Operation Excellence',
            'P': 'Performance Efficiency',
            'S': 'Security',
            'R': 'Reliability',
            'C': 'Cost Optimization'
        }
        return mapped[category]
        
    def _getCriticallyName(self, criticality):
        mapped = {
            'H': 'High',
            'M': 'Medium',
            'L': 'Low',
            'I': 'Informational'
        }
        
        return mapped[criticality]
    
    def _formatHyperlink(self, arr):
        if not arr:
            return ''
        
        recomm = []
        for p in arr:
            o = p.find("href='")
            e = p.find("'>")
            r = p[o+6:e-6]
            w = p[e+2:-4]
            recomm.append(f"{w}, {r}")
        return '\n'.join(recomm)