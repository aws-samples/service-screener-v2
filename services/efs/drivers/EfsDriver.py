from services.Evaluator import Evaluator

class EfsDriver(Evaluator):
    def __init__(self, efs, efs_client):
        self.efs = efs
        self.efs_client = efs_client
        self.__config_prefix = 'efs::'

        self.results = {}
        self.init()

    def _checkEncrypted(self):
        self.results['EncryptedAtRest'] = [1, 'Enabled']
        if self.efs['Encrypted'] != 1:
            self.results['EncryptedAtRest'] = [-1, 'Disabled']

    def _checkLifecycle_configuration(self):
        self.results['Lifecycle'] = [1, 'Enabled']
        efs_id = self.efs['FileSystemId']

        life_cycle = self.efs_client.describe_lifecycle_configuration(
            FileSystemId=efs_id
        )

        if len(life_cycle['LifecyclePolicies']) == 0:
            self.results['EnabledLifecycle'] = [-1, 'Disabled']

    def _checkBackupPolicy(self):
        self.results['AutomatedBackup'] = [1, 'Enabled']
        efs_id = self.efs['FileSystemId']

        backup = self.efs_client.describe_backup_policy(
            FileSystemId=efs_id
        )

        if backup['BackupPolicy']['Status'] == 'DISABLED':
            self.results['AutomatedBackup'] = [-1, 'Disabled']
