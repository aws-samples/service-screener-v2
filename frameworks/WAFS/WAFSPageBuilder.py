from frameworks.FrameworkPageBuilder import FrameworkPageBuilder
from utils.Config import Config


class WAFSPageBuilder(FrameworkPageBuilder):
    def init(self):
        super().__init__()
        self.template = 'default'

    def buildContentSummary(self):
        """Override to add WA Report download link at the top of the summary."""
        output = super().buildContentSummary()

        # Add WA Report download link if report was generated
        wa_report_filename = Config.get('WA_REPORT_FILENAME', None)
        if wa_report_filename:
            download_html = self._buildWAReportDownloadCard(wa_report_filename)
            # Insert at the beginning of the output
            output.insert(0, download_html)

        return output

    def _buildWAReportDownloadCard(self, report_filename):
        """Generate an HTML card with a download link for the WA lens review report."""
        html = f"""
        <div class="alert alert-success" role="alert">
            <h5><i class="fas fa-file-pdf"></i> Well-Architected Lens Review Report</h5>
            <p>A PDF report has been generated from the AWS Well-Architected Tool for this workload.
            This report includes your responses, identified risks, and improvement plans.</p>
            <a href="{report_filename}" download class="btn btn-primary btn-sm">
                <i class="fas fa-download"></i> Download WA Report (PDF)
            </a>
        </div>
        """
        return html
