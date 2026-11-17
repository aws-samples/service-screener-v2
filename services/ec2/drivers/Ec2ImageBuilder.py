import botocore

from services.Evaluator import Evaluator

# Stock (publicly published) Amazon AMIs: no in-house image build step.
# AWS Marketplace AMIs are not counted: they are often vendor appliances
# (firewalls, NVAs) meant to run as published and cannot be rebuilt in-house.
STOCK_OWNER_ALIASES = ('amazon',)
IMAGEBUILDER_TAG = 'Ec2ImageBuilderArn'


def _errCode(e):
    if isinstance(e, botocore.exceptions.ClientError):
        return e.response.get('Error', {}).get('Code', 'ClientError')
    return type(e).__name__


class Ec2ImageBuilder(Evaluator):
    """Region-level: are EC2 instances launched from images produced by a build
    pipeline? Image Builder is one of several valid tools (Packer, a central image
    factory account), so only the unambiguous case FAILs: no enabled Image Builder
    pipeline in the region AND instances run stock Amazon AMIs as-is.
    Self-owned, cross-account or AWS Marketplace (vendor appliance) AMIs are INFO."""

    def __init__(self, ibClient, ec2Client, instances):
        super().__init__()
        self.ibClient = ibClient
        self.ec2Client = ec2Client
        self.instances = instances or []

        self._resourceName = f"EC2-ImageBuilder-{ec2Client.meta.region_name}"

        self.init()

    def _pipelines(self):
        out = []
        for page in self.ibClient.get_paginator('list_image_pipelines').paginate():
            out.extend(page.get('imagePipelineList', []) or [])
        return out

    def _images(self, imageIds):
        found = {}
        ids = sorted(imageIds)
        for i in range(0, len(ids), 100):
            batch = ids[i:i+100]
            try:
                resp = self.ec2Client.describe_images(ImageIds=batch, IncludeDeprecated=True)
            except botocore.exceptions.ClientError as e:
                if _errCode(e) not in ('InvalidAMIID.NotFound', 'InvalidAMIID.Unavailable', 'InvalidAMIID.Malformed'):
                    raise
                # one unknown/deregistered AMI fails the whole batch: look them up one by one
                for iid in batch:
                    try:
                        resp = self.ec2Client.describe_images(ImageIds=[iid], IncludeDeprecated=True)
                    except botocore.exceptions.ClientError as e2:
                        if _errCode(e2).startswith('InvalidAMIID'):
                            continue
                        raise
                    for img in resp.get('Images', []):
                        found[img['ImageId']] = img
                continue
            for img in resp.get('Images', []):
                found[img['ImageId']] = img
        return found

    def _checkImagebuilderNoPipeline(self):
        key = 'imagebuilderNoPipeline'
        live = [i for i in self.instances if (i.get('State') or {}).get('Name') in ('pending', 'running', 'stopping', 'stopped')]
        if not live:
            self.results[key] = [1, 'No EC2 instances in region']
            return
        try:
            pipelines = self._pipelines()
        except Exception as e:
            self.results[key] = [0, f"Unable to evaluate ({_errCode(e)})"]
            return
        enabled = [p for p in pipelines if str(p.get('status', '')).upper() == 'ENABLED']
        if enabled:
            self.results[key] = [1, f"{len(enabled)} enabled Image Builder pipeline(s)"]
            return
        disabledNote = f" ({len(pipelines)} disabled pipeline(s))" if pipelines else ''

        try:
            images = self._images({i.get('ImageId') for i in live if i.get('ImageId')})
        except Exception as e:
            self.results[key] = [0, f"Unable to evaluate ({_errCode(e)}){disabledNote}"]
            return

        stock, built, unknown = [], [], []
        for inst in live:
            img = images.get(inst.get('ImageId'))
            if img is None:
                unknown.append(inst['InstanceId'])
                continue
            tags = {t.get('Key') for t in img.get('Tags', []) or []}
            if img.get('ImageOwnerAlias') in STOCK_OWNER_ALIASES and IMAGEBUILDER_TAG not in tags:
                stock.append(f"{inst['InstanceId']} ({img['ImageId']})")
            else:
                built.append(inst['InstanceId'])

        if stock:
            shown = ', '.join(stock[:5]) + (f" (+{len(stock) - 5} more)" if len(stock) > 5 else '')
            self.results[key] = [-1, f"No enabled Image Builder pipeline{disabledNote}; {len(stock)}/{len(live)} instance(s) run stock Amazon AMIs: {shown}"]
        elif built:
            self.results[key] = [0, f"No enabled Image Builder pipeline{disabledNote}; instances use custom, cross-account or Marketplace AMIs - verify they come from a hardened image pipeline (Packer, central image factory, ...)"]
        else:
            self.results[key] = [0, f"Unable to evaluate (source AMIs of {len(unknown)} instance(s) not readable){disabledNote}"]
