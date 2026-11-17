from services.Evaluator import Evaluator


class FsxFileSystem(Evaluator):
    """Checks for a single Amazon FSx file system (data comes from describe_file_systems)."""

    TYPE_CONFIG_KEY = {
        'WINDOWS': 'WindowsConfiguration',
        'LUSTRE': 'LustreConfiguration',
        'ONTAP': 'OntapConfiguration',
        'OPENZFS': 'OpenZFSConfiguration',
    }

    ## Lustre scratch file systems do not support backups at all
    LUSTRE_NO_BACKUP_DEPLOYMENTS = ('SCRATCH_1', 'SCRATCH_2')

    def __init__(self, fs, fsxClient):
        super().__init__()
        self.fs = fs
        self.fsxClient = fsxClient
        self._resourceName = fs.get('FileSystemId', 'unknown')
        self.init()

    def _checkFsxAutomaticBackupDisabled(self):
        key = 'fsxAutomaticBackupDisabled'
        fsType = self.fs.get('FileSystemType')
        lifecycle = self.fs.get('Lifecycle')
        cfgKey = self.TYPE_CONFIG_KEY.get(fsType)

        if lifecycle in ('DELETING', 'FAILED'):
            self.results[key] = [0, f'Unable to evaluate (file system is {lifecycle})']
            return
        if cfgKey is None:
            self.results[key] = [0, f'Unable to evaluate (unknown file system type {fsType})']
            return

        cfg = self.fs.get(cfgKey) or {}

        if fsType == 'LUSTRE':
            deployment = cfg.get('DeploymentType')
            if deployment in self.LUSTRE_NO_BACKUP_DEPLOYMENTS:
                self.results[key] = [0, f'Automatic backups not supported on Lustre {deployment} file systems']
                return
            ## Legacy S3 linking (ImportPath) on persistent file systems does not support backups
            if cfg.get('DataRepositoryConfiguration'):
                self.results[key] = [0, 'Automatic backups not supported on Lustre file systems linked to S3 via ImportPath']
                return

        days = cfg.get('AutomaticBackupRetentionDays')
        if days is None:
            self.results[key] = [0, 'Unable to evaluate (AutomaticBackupRetentionDays not returned)']
            return

        if days == 0:
            self.results[key] = [-1, f'{fsType}: AutomaticBackupRetentionDays is 0']
        else:
            self.results[key] = [1, f'{fsType}: automatic backups retained {days} day(s)']
