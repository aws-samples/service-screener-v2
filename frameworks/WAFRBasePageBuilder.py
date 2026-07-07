import json
from frameworks.FrameworkPageBuilder import FrameworkPageBuilder


class WAFRBasePageBuilder(FrameworkPageBuilder):
    """
    Shared PageBuilder for all WAFR pillar frameworks.
    Injects a 'Download WAFR Report' button when the framework produced a PDF.
    """

    def init(self):
        super().init()
        self.template = 'default'

    def _postBuildContentDetailHook(self):
        """If the framework produced a Well-Architected Review PDF, inject a
        download button into the top-right of the HTML page."""
        report_filename = getattr(self.framework, 'reportFilename', None)
        if report_filename:
            self._injectWAFRDownloadButton(report_filename)

    def _injectWAFRDownloadButton(self, report_filename):
        fname_literal = json.dumps(str(report_filename)).replace('</', '<\\/')
        js = """
(function(){
  var fname = %s;
  var $bcRow = $('.content-header .container-fluid .row.mb-2').first();
  if(!$bcRow.length) return;
  if($bcRow.find('a.wafr-download-btn').length) return;
  var btnHtml = "<a class='btn btn-primary btn-sm wafr-download-btn float-sm-right ml-2' "
              + "href='" + encodeURI(fname) + "' download target='_blank' rel='noopener noreferrer' "
              + "title='Download Well-Architected Framework Review Report (PDF)'>"
              + "<i class='fas fa-file-download'></i> Download WAFR Report</a>";
  var $rightCol = $bcRow.children('.col-sm-6').last();
  if($rightCol.length){
    $rightCol.prepend(btnHtml);
  } else {
    $bcRow.append("<div class='col-sm-6'>" + btnHtml + "</div>");
  }
})();
""" % fname_literal
        self.addJS(js)
