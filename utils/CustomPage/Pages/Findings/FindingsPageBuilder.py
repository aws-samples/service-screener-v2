import json
from utils.CustomPage.CustomPageBuilder import CustomPageBuilder
from utils.Config import Config
import openpyxl
import constants as _C

class FindingsPageBuilder(CustomPageBuilder):
    SHEETS_TO_SKIP = ['Info', 'Appendix']
    
    FRAMEWORK_JS_LIB = [
        "/jquery.dataTables.min.js",
        "-bs4/js/dataTables.bootstrap4.min.js",
        "-responsive/js/dataTables.responsive.min.js",
        "-responsive/js/responsive.bootstrap4.min.js",
        "-buttons/js/dataTables.buttons.min.js",
        "-buttons/js/buttons.bootstrap4.min.js",
        "-buttons/js/buttons.html5.min.js",
        "-buttons/js/buttons.print.min.js",
        "-buttons/js/buttons.colVis.min.js"
    ]
    FRAMEWORK_CSS_LIB = [
        "bs4/css/dataTables.bootstrap4.min.css",
        "responsive/css/responsive.bootstrap4.min.css",
        "buttons/css/buttons.bootstrap4.min.css"
    ]
    
    def customPageInit(self):
        self.wb = openpyxl.load_workbook(_C.ROOT_DIR + '/' + Config.get('HTML_ACCOUNT_FOLDER_PATH') + '/workItem.xlsx')
        self.initCSS()
        self.initJSLib()
        return
    
    def initJSLib(self):
        pref = '../res/plugins/datatables'
        for js in self.FRAMEWORK_JS_LIB:
            self.addJSLib(pref + js)
            
    def initCSS(self):
        pref = "../res/plugins/datatables-"
        for css in self.FRAMEWORK_CSS_LIB:
            self.addCSSLib(pref + css)
    
    def getSheetTitle(self):
        columnTitles = ['Service']
        wb = self.wb
        for sheetName in wb.sheetnames:
            if sheetName in self.SHEETS_TO_SKIP:
                continue
            

            ws = wb[sheetName]
            for i in range(1, ws.max_column +1):
                columnTitles.append(ws.cell(row=1, column=i).value)
            return columnTitles
        
    def genTableHTML(self):
        wb = self.wb
        columnTitles = self.getSheetTitle()
        
        tableHTMLList = [
            "<table id='findings-table' class='table table-bordered table-striped'>",
            "<thead><tr>"
        ]

        if not columnTitles:
            return ''

        for title in columnTitles:
            tableHTMLList.append("<th>" + title + "</th>")
        tableHTMLList.append("</tr></thead>")
        
        tableHTMLList.append("<tbody>")
        for sheetName in wb.sheetnames:
            if sheetName not in self.SHEETS_TO_SKIP:
                ws = wb[sheetName]
                for i in range(2, ws.max_row + 1):
                    tableHTMLList.append("<tr><td>" + sheetName + "</td>")
                    for j in range (1, ws.max_column + 1):
                        tableHTMLList.append("<td>" + ws.cell(row=i, column=j).value + "</td>")
                    tableHTMLList.append("</tr>")
        
        tableHTMLList.append("</tbody></table>")
        
        return ''.join(tableHTMLList)
        
    
    def buildContentSummary_customPage(self):
        output = []
        
        card = self.generateCard(pid=self.getHtmlId('Findings'), html=self.genTableHTML(), cardClass='warning', title='Findings', titleBadge='', collapse=True, noPadding=False)
        items = [[card, '']]
        
        output.append(self.generateRowWithCol(12, items, "data-context='settingTable'"))
        
        
        return output
    
    def buildContentDetail_customPage(self):
        js = '''
myTab = $("#findings-table").DataTable({
      "responsive": true, "lengthChange": true, "autoWidth": false,
      "pageLength": 50,
      "buttons": ["copy", "csv", "colvis"]
    })
myTab.buttons().container().appendTo('#findings-table_wrapper .col-md-6:eq(0)');

var hash = window.location.hash.slice(1);
if (hash){
  myTab.search(decodeURI(hash)).draw()
}
'''

        self.addJS(js)
        return
    