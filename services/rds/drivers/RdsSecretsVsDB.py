import boto3

import time
import datetime

from utils.Config import Config
from utils.Tools import _pr
from utils.Tools import aws_parseInstanceFamily
from utils.Tools import _warn
from services.Evaluator import Evaluator

class RdsSecretsVsDB(Evaluator):
    def __init__(self, noOfSecret, noOfDB):
        super().__init__()
        self.noOfSecret = noOfSecret
        self.noOfDB = noOfDB

        self._resourceName = 'SecretCount#'
        
        self.init()

    def _checkSecretDBRatio(self):
        if self.noOfDB > 0:
            if self.noOfSecret == 0:
                self.results['DBwithoutSecretManager'] = [-1, self.__formResponseStr()]
                return
            elif self.noOfDB > self.noOfSecret:
                self.results['DBwithSomeSecretsManagerOnly'] = [-1, self.__formResponseStr()]
                return
            
    def __formResponseStr(self):
        return "#Secrets: " + str(self.noOfSecret) + " |  #DB: " + str(self.noOfDB)