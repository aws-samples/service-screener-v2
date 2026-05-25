from frameworks.FrameworkPageBuilder import FrameworkPageBuilder
import json


class WAFSPageBuilder(FrameworkPageBuilder):
    def init(self):
        super().init()
        self.template = 'default'

    def _postBuildContentDetailHook(self):
        """If the WAFS framework produced a Well-Architected Framework Review
        report PDF (see ``WAFS._hookPostBuildContentDetail``), inject a
        download button into the top-right of WAFS.html.

        The filename is read directly from the framework instance to avoid
        cross-component coupling through global Config / temporal ordering."""
        report_filename = getattr(self.framework, 'reportFilename', None)
        if report_filename:
            self._injectWAFRDownloadButton(report_filename)

    def _injectWAFRDownloadButton(self, report_filename):
        # Use json.dumps to safely embed the filename as a JS string literal
        # (handles quotes, backslashes, newlines and control chars). Also
        # neutralize ``</`` so the value cannot prematurely close the
        # surrounding ``<script>`` block when written into the HTML page.
        fname_literal = json.dumps(str(report_filename)).replace('</', '<\\/')

        # The PDF is written to the same account folder as WAFS.html, so a
        # relative href works for both local viewing and the zipped output
        # bundle.
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
