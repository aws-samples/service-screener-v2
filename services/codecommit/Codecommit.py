import botocore

from utils.Tools import _pi
from services.Service import Service

from services.codecommit.drivers.CodecommitRepository import CodecommitRepository


class Codecommit(Service):
    """
    AWS CodeCommit scanner (read-only).

    Discovery: list_repositories (paginated) -> batch_get_repositories (25 per
    call, for ARN/defaultBranch) -> list_tags_for_resource (only when a tag
    filter is in use). Each repository is handed to CodecommitRepository,
    which reads its associated approval rule templates.
    """

    BATCH_SIZE = 25

    def __init__(self, region):
        super().__init__(region)
        ssBoto = self.ssBoto
        self.ccClient = ssBoto.client('codecommit', config=self.bConfig)

    def getResources(self):
        names = []
        try:
            paginator = self.ccClient.get_paginator('list_repositories')
            for page in paginator.paginate():
                names += [r.get('repositoryName') for r in page.get('repositories', []) or []
                          if r.get('repositoryName')]
        except botocore.exceptions.EndpointConnectionError as e:
            print(f"CodeCommit not available in region {self.region}: {e}")
            return []
        except botocore.exceptions.ClientError as e:
            code = e.response.get('Error', {}).get('Code', 'Unknown')
            print(f"Codecommit list_repositories: {code}")
            return []

        repos = []
        for i in range(0, len(names), self.BATCH_SIZE):
            chunk = names[i:i + self.BATCH_SIZE]
            metaError = None
            try:
                resp = self.ccClient.batch_get_repositories(repositoryNames=chunk)
                found = {r.get('repositoryName'): r for r in resp.get('repositories', []) or []}
            except botocore.exceptions.ClientError as e:
                metaError = e.response.get('Error', {}).get('Code', 'Unknown')
                print(f"Codecommit batch_get_repositories: {metaError}")
                found = {}
            for n in chunk:
                ## '_metadataError' marks a repository whose defaultBranch is unknown
                ## because its metadata could not be read (not because it is empty).
                repos.append(found.get(n) or {'repositoryName': n,
                                              '_metadataError': metaError or 'RepositoryMetadataNotReturned'})

        if not self.tags:
            return repos

        filtered = []
        for repo in repos:
            arn = repo.get('Arn')
            if not arn:
                continue
            tags, token = {}, None
            try:
                while True:
                    kwargs = {'resourceArn': arn}
                    if token:
                        kwargs['nextToken'] = token
                    resp = self.ccClient.list_tags_for_resource(**kwargs)
                    tags.update(resp.get('tags', {}) or {})
                    token = resp.get('nextToken')
                    if not token:
                        break
            except botocore.exceptions.ClientError:
                continue
            if self.resourceHasTags(self.convertKeyPairTagToTagFormat(tags)):
                filtered.append(repo)
        return filtered

    def advise(self):
        objs = {}
        templateCache = {}
        for repo in self.getResources():
            name = repo.get('repositoryName')
            _pi('CodeCommit', name)
            obj = CodecommitRepository(repo, self.ccClient, templateCache)
            obj.run(self.__class__)
            objs[f"Repository::{name}"] = obj.getInfo()
            del obj
        return objs
