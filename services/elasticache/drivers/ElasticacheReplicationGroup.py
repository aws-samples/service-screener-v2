from services.Evaluator import Evaluator


class ElasticacheReplicationGroup(Evaluator):
    def __init__(self, driver_info):
        super().__init__()
        self.names = driver_info['names']

    # for all redis replication grups (not cluster node), need to check if a snapshot exists
    # for all replciaiton groups need to check if len(set(PerferredAvailabilityZone)) > 1