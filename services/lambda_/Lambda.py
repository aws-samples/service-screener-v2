import boto3
from botocore.exceptions import ClientError
# import os
# import importlib

from services.lambda_.drivers.LambdaCommon import LambdaCommon
from services.Service import Service
from utils.Config import Config

class Lambda(Service):
    def __init__(self, region):
        super().__init__(region)
        self.region = region
        
        ssBoto = self.ssBoto
        self.lambda_client = ssBoto.client("lambda", config=self.bConfig)
        self.iam_client = ssBoto.client("iam", config=self.bConfig)
        self.tags = []

    def get_resources(self):
        functions = []
        next_token = None

        while True:
            if next_token:
                response = self.lambda_client.list_functions(Marker=next_token)
            else:
                response = self.lambda_client.list_functions()

            functions.extend(response["Functions"])

            if "NextMarker" in response:
                next_token = response["NextMarker"]
            else:
                break

        if not self.tags:
            return functions

        filtered_functions = []

        for function in functions:
            try:
                response = self.lambda_client.list_tags(
                    Resource=function["FunctionArn"]
                )
                tags = response["Tags"]
                if self.resource_has_tags(tags):
                    filtered_functions.append(function)
            except ClientError as e:
                print(f"Error listing tags for {function['FunctionArn']}: {e}")

        return filtered_functions

    def resource_has_tags(self, tags):
        for tag in self.tags:
            key = tag["Name"].replace("tag:", "")
            value = tag["Values"][0]
            if key in tags and tags[key] == value:
                return True
        return False

    def advise(self):
        objs = {}
        func_role_map = {}
        role_count = {}

        lambdas = self.get_resources()

        for lambda_function in lambdas:
            role = lambda_function["Role"]
            if role not in role_count:
                role_count[role] = 0
            role_count[role] += 1
            func_role_map[lambda_function["FunctionArn"]] = role

        for lambda_function in lambdas:
            driver = "lambda_common"

            try:
                # module = importlib.import_module(f"drivers.{driver}")
                # cls = getattr(module, driver)
                print(f"... (Lambda) inspecting {lambda_function['FunctionName']}")
                # obj = cls(lambda_function, self.lambda_client, self.iam_client, role_count)
                obj = LambdaCommon(lambda_function, self.lambda_client, self.iam_client, role_count)
                obj.run(self.__class__)
                objs[f"Lambda::{lambda_function['FunctionName']}"] = obj.getInfo()
            except (ImportError, AttributeError):
                print(f"Failed to load driver {driver}")

        return objs
            
            
if __name__ == "__main__":
    Config.init()
    o = Lambda('ap-southeast-1')
    out = o.get_resources()
    print(out)
