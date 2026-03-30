import boto3
import botocore
from datetime import datetime, timedelta

from services.Evaluator import Evaluator


class CrawlerDriver(Evaluator):
    """
    Driver for checking AWS Glue Crawler configurations.
    
    This driver evaluates crawler operational settings:
    - Schedule configuration
    """
    
    def __init__(self, crawler, glueClient):
        """
        Initialize CrawlerDriver.
        
        Args:
            crawler (dict): Crawler configuration from get_crawler() or list_crawlers()
            glueClient: Boto3 Glue client for API calls
        """
        super().__init__()
        self.crawler = crawler
        self.glueClient = glueClient
        
        # Set resource name to unique identifier
        self._resourceName = f"Crawler::{crawler['Name']}"
        
        # Initialize check discovery
        self.init()
        
        # Store metadata using addII (after init() to avoid being cleared)
        self.addII('crawlerName', crawler['Name'])
        self.addII('state', crawler.get('State', 'N/A'))
        self.addII('creationTime', str(crawler.get('CreationTime', 'N/A')))
        self.addII('lastUpdated', str(crawler.get('LastUpdated', 'N/A')))
        self.addII('schedule', crawler.get('Schedule', {}).get('ScheduleExpression', 'None'))
    
    def _checkScheduleConfigured(self):
        """
        Check if the crawler has a schedule configured.
        
        Crawlers without schedules may not run regularly to keep the Data Catalog
        up-to-date with changes in data sources.
        
        Reporter JSON key: CrawlerScheduleConfigured
        """
        try:
            schedule = self.crawler.get('Schedule')
            
            if not schedule:
                self.results['CrawlerScheduleConfigured'] = [-1, 'No Schedule Configured']
                return
            
            scheduleExpression = schedule.get('ScheduleExpression')
            scheduleState = schedule.get('State', 'UNKNOWN')
            
            if not scheduleExpression:
                self.results['CrawlerScheduleConfigured'] = [-1, 'No Schedule Expression']
                return
            
            # Check if schedule is active
            if scheduleState == 'SCHEDULED':
                self.results['CrawlerScheduleConfigured'] = [1, f'Scheduled: {scheduleExpression}']
            elif scheduleState == 'NOT_SCHEDULED':
                self.results['CrawlerScheduleConfigured'] = [-1, f'Schedule exists but not active: {scheduleExpression}']
            else:
                self.results['CrawlerScheduleConfigured'] = [0, f'Schedule state: {scheduleState}, Expression: {scheduleExpression}']
            
        except Exception as e:
            print(f"Error checking schedule for crawler {self.crawler['Name']}: {e}")
            self.results['CrawlerScheduleConfigured'] = [0, f'Error: {str(e)}']
