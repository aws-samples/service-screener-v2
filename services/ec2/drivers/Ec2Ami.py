from services.Evaluator import Evaluator


class Ec2Ami(Evaluator):
    """Per-AMI checks for images owned by this account (describe_images(Owners=['self']))."""

    def __init__(self, image):
        super().__init__()
        self.image = image

        self._resourceName = image['ImageId']

        self.init()

    def _checkEc2AmiPublic(self):
        image = self.image
        isPublic = image.get('Public')
        name = image.get('Name') or ''
        if isPublic is True:
            self.results['ec2AmiPublic'] = [-1, f"Public (launch permission group 'all'){' - ' + name if name else ''}"]
        elif isPublic is False:
            self.results['ec2AmiPublic'] = [1, 'Private']
        else:
            self.results['ec2AmiPublic'] = [0, 'Unable to evaluate (Public attribute not returned)']
