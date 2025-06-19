from frameworks.FrameworkPageBuilder import FrameworkPageBuilder

class SOC2PageBuilder(FrameworkPageBuilder):
    def init(self):
        super().__init__()
        self.template = 'default'
        
    def _hookPostBuildContent(self):
        # Add documentation references to the HTML output
        self.content += """
        <div class="card">
            <div class="card-header">
                <h3 class="card-title">SOC2 Documentation Resources</h3>
            </div>
            <div class="card-body">
                <p>The following documentation resources are available to help with SOC2 compliance:</p>
                <ul>
                    <li><strong>Implementation Guide</strong>: Step-by-step guide for implementing SOC2 compliance in AWS</li>
                    <li><strong>Remediation Guide</strong>: Detailed remediation steps for common findings</li>
                    <li><strong>AWS Mapping Guide</strong>: Comprehensive mapping between SOC2 criteria and AWS services</li>
                </ul>
                <p>These files are located in the frameworks/SOC2 directory of the service-screener-v2 repository.</p>
            </div>
        </div>
        """
        return super()._hookPostBuildContent()
