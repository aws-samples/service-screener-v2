"""
Cost Optimization Hub Page Builder

This module generates HTML pages for the Cost Optimization Hub custom page.
It provides a redirect message to the Cloudscape UI where the full COH functionality is available.
"""

from utils.CustomPage.CustomPageBuilder import CustomPageBuilder


class COHPageBuilder(CustomPageBuilder):
    """
    Page builder for Cost Optimization Hub
    
    Inherits from CustomPageBuilder to integrate with Service Screener's page generation
    infrastructure. Provides a simple redirect message to the Cloudscape UI.
    """
    
    def __init__(self, service='coh', reporter=None):
        super().__init__(service, reporter)
    
    def customPageInit(self):
        """Initialize custom page - simplified for Cloudscape redirect"""
        # No additional initialization needed since we're redirecting to Cloudscape UI
        return
    
    def buildContentSummary_customPage(self):
        """Build summary content for the COH page - Cloudscape UI redirect"""
        cloudscape_message = """
        <div class="alert alert-info" role="alert">
            <h4 class="alert-heading"><i class="fas fa-info-circle"></i> Feature Available in Cloudscape UI</h4>
            <p>The Cost Optimization Hub is now available in our modern Cloudscape UI interface, which provides:</p>
            <ul>
                <li>Interactive dashboards and visualizations</li>
                <li>Advanced filtering and sorting capabilities</li>
                <li>Export functionality for recommendations</li>
                <li>Enhanced user experience with modern design</li>
            </ul>
            <hr>
            <p class="mb-0">
                <strong>Please use the Cloudscape UI version for the full Cost Optimization Hub experience.</strong>
            </p>
        </div>
        """
        
        return [cloudscape_message]
    
    def buildContentDetail_customPage(self):
        """Build detailed content for the COH page - Cloudscape UI redirect"""
        return []