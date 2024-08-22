import boto3
import botocore
import constants as _C

from services.Evaluator import Evaluator

class EcsTaskDefinition(Evaluator):

    def __init__(self, taskDefName, ecsClient):
        super().__init__()
        self.taskDefName = taskDefName
        self.ecsClient = ecsClient
        self.init()
    
    def _checkReadOnlyRootFileSystem(self):
        try:
            response = self.ecsClient.describe_task_definition(
                taskDefinition = self.taskDefName,
            )

        except:
            print("Exception", self.taskDefName)
        containerDefJSON = response.get('taskDefinition').get('containerDefinitions')[0]
        if 'readonlyRootFilesystem' in containerDefJSON:
            readOnlyFlag = containerDefJSON['readonlyRootFilesystem']
            if readOnlyFlag is False:
                self.results['ecsTaskDefinitionReadOnlyRootFilesystem'] = [-1, "readOnlyRootFilesystem is False"]
        
        else:
            self.results['ecsTaskDefinitionReadOnlyRootFilesystem'] = [-1, "readOnlyRootFilesystem is False"]