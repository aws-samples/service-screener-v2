import json
from utils.CustomPage.CustomPageBuilder import CustomPageBuilder
from utils.Config import Config
import constants as _C

class TAPageBuilder(CustomPageBuilder):
    hasError = False
    def customPageInit(self):
        if not self.data.taError == '':
            self.hasError = True
            
        return

    def buildContentSummary_customPage(self):
        if self.hasError:
            return ["<span>{}</span>".format(self.data.taError)]
        # info = self.data.taFindings

        pass

    def buildContentDetail_customPage(self):
        if self.hasError:
            return

        output = []
        
        for pillar, pillarInfo in self.data.taFindings.items():
            rows = pillarInfo[0]
            head = pillarInfo[1]
            summ = pillarInfo[2]

            op = self.formatOutput(pillar, head, rows)

            cardTitle = "{} <span class='badge badge-danger'>{} Error</span> <span class='badge badge-warning'>{} Warning</span> <span class='badge badge-success'>{} Ok</span>".format(pillar, summ['Error'], summ['Warning'], summ['OK'])

            card = self.generateCard(pid=self.getHtmlId(pillar), html=op, cardClass='primary', title=cardTitle, titleBadge='', collapse=True, noPadding=False)
            items = [[card, '']]
        
            output.append(self.generateRowWithCol(12, items, "data-context='settingTable'"))

        return output

    def formatOutput(self, title, thead, rowInfo):
        htmlO = []
        htmlO.append("<table class='table table-bordered table-hover'>")
        
        fieldSize = len(thead)
        for headInfo in thead:
            htmlO.append(f"<th>{headInfo}</th>")

        for row in rowInfo:
            # print(row)
            htmlO.append("<tr data-widget='expandable-table' aria-expanded='false'>")
            for i in range(fieldSize):
                htmlO.append(f"<td>{row[i]}</td>")
            htmlO.append("</tr>")
            htmlO.append("<tr class='expandable-body d-none'><td colspan={}><p style='display: none;'>{}</p></td></tr>".format(fieldSize, row[fieldSize]))

        htmlO.append("</table>")
        return ''.join(htmlO)