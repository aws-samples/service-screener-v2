import tempfile
import base64
from datetime import datetime, timedelta
from services.Service import Service
from services.eks.drivers.EksCommon import EksCommon
from kubernetes import client as k8sClient, config as k8sConfig
from awscli.customizations.eks.get_token import STSClientFactory, TokenGenerator, TOKEN_EXPIRATION_MINS
from botocore import session


class K8sClient:
    """
    k8s client to be used to call Kubernetes APIs
    """
    def __init__(self, cluster_info):
        self.clusterInfo = cluster_info
        self.workSession = session.get_session()
        self.stsClientFactory = STSClientFactory(self.workSession)
        self.CoreV1Client = k8sClient.CoreV1Api(api_client=self.client())
        self.PolicyV1Client = k8sClient.PolicyV1Api(api_client=self.client())
        self.NetworkingV1Client = k8sClient.NetworkingV1Api(api_client=self.client())
        self.CustomObjectsClient = k8sClient.CustomObjectsApi(api_client=self.client())
        self.AutoscalingV2Api = k8sClient.AutoscalingV2Api(api_client=self.client())
        self.AppsV1Api = k8sClient.AppsV1Api(api_client=self.client())

    def writeCaFile(self, data: str) -> tempfile.NamedTemporaryFile:
        """
        Generate Cluster CA file

        :param data: Get CA data from clusterInfo

        :return:
        """
        # protect yourself from automatic deletion
        ca_file = tempfile.NamedTemporaryFile(delete=False)
        ca_data_b64 = data
        ca_data = base64.b64decode(ca_data_b64)
        ca_file.write(ca_data)
        ca_file.flush()
        return ca_file

    def _config(self):
        """
        Kubernetes Configuration
        :return:
        """
        config = k8sConfig.kube_config.Configuration(
            host=self.clusterInfo['endpoint'],
            api_key={'authorization': 'Bearer ' + self.get_token()['status']['token']}
        )

        config.ssl_ca_cert = self.writeCaFile(self.clusterInfo['certificateAuthority']['data']).name
        return config

    def client(self):
        return k8sClient.ApiClient(configuration=self._config())

    def get_expiration_time(self):
        token_expiration = datetime.utcnow() + timedelta(minutes=TOKEN_EXPIRATION_MINS)
        return token_expiration.strftime('%Y-%m-%dT%H:%M:%SZ')

    def get_token(self, role_arn: str = None) -> dict:
        sts_client = self.stsClientFactory.get_sts_client(role_arn=role_arn)
        token = TokenGenerator(sts_client).get_token(self.clusterInfo.get("name"))
        return {
            "kind": "ExecCredential",
            "apiVersion": "client.authentication.k8s.io/v1beta1",
            "spec": {},
            "status": {
                "expirationTimestamp": self.get_expiration_time(),
                "token": token
            }
        }

class Eks(Service):
    def __init__(self, region):
        super().__init__(region)
        ssBoto = self.ssBoto
        self.eksClient = ssBoto.client('eks', config=self.bConfig)
        self.ec2Client = ssBoto.client('ec2', config=self.bConfig)
        self.iamClient = ssBoto.client('iam')
    def getClusters(self):
        arr = []
        results = self.eksClient.list_clusters()
        arr = results.get('clusters')
        while results.get('nextToken') is not None:
            results = self.eksClient.list_clusters(
                nextToken = results.get('nextToken')
            )
            arr = arr + results.get('clusters')
        return arr
    def describeCluster(self, clusterName):
        response = self.eksClient.describe_cluster(
            name = clusterName
        )
        return response.get('cluster')
    
    def listInsights(self, clusterName):
        response = self.eksClient.list_insights(
            clusterName = clusterName
        )
        return response.get('insights')

    def advise(self):
        objs = {}
        clusters = self.getClusters()
        for cluster in clusters:
            print('...(EKS:Cluster) inspecting ' + cluster)
            clusterInfo = self.describeCluster(cluster)
            updateInsights = self.listInsights(cluster)
            # K8sClient = self.generateK8sClient(cluster, clusterInfo)
            #if clusterInfo.get('status') == 'CREATING':
            #    print(cluster + " cluster is creating. Skipped")
            #    continue
            if self.tags:
                resp = self.eksClient.list_tags_for_resource(resourceArn=clusterInfo['arn'])
                nTags = self.convertKeyPairTagToTagFormat(resp.get('tags'))
                if self.resourceHasTags(nTags) == False:
                    continue
            obj = EksCommon(cluster, clusterInfo, updateInsights, self.eksClient, self.ec2Client, self.iamClient, K8sClient)
            obj.run(self.__class__)
            objs['Cluster::' + cluster] = obj.getInfo()
        return objs