import botocore

from services.Evaluator import Evaluator
from services.ec2.drivers.Ec2UserDataScan import decodeUserData, findSecrets


class Ec2LaunchTemplate(Evaluator):
    """Launch template user data must not embed credentials. Every version is
    scanned: old versions stay readable (ec2:DescribeLaunchTemplateVersions) and
    launchable until they are deleted."""

    def __init__(self, template, ec2Client):
        super().__init__()
        self.template = template
        self.ec2Client = ec2Client

        self._resourceName = template['LaunchTemplateId']

        self.init()

    def _checkEc2UserDataSecrets(self):
        key = 'ec2UserDataSecrets'
        try:
            versions = []
            paginator = self.ec2Client.get_paginator('describe_launch_template_versions')
            for page in paginator.paginate(LaunchTemplateId=self.template['LaunchTemplateId']):
                versions.extend(page.get('LaunchTemplateVersions', []))
        except botocore.exceptions.ClientError as e:
            self.results[key] = [0, f"Unable to evaluate ({e.response.get('Error', {}).get('Code', 'ClientError')})"]
            return

        flagged = []
        withUserData = 0
        for v in sorted(versions, key=lambda x: x.get('VersionNumber', 0)):
            userData = (v.get('LaunchTemplateData') or {}).get('UserData')
            if not userData:
                continue
            withUserData += 1
            found = findSecrets(decodeUserData(userData))
            if found:
                default = ' default' if v.get('DefaultVersion') else ''
                flagged.append(f"v{v.get('VersionNumber')}{default}: {', '.join(found)}")

        if flagged:
            self.results[key] = [-1, 'User data contains credentials (values masked) - ' + '; '.join(flagged)]
        elif withUserData:
            self.results[key] = [1, f"No credential patterns in {withUserData} version(s) with user data"]
        else:
            self.results[key] = [1, 'No user data']
