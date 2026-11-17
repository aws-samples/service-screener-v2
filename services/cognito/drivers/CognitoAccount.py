from services.Evaluator import Evaluator


class CognitoAccount(Evaluator):
    """
    Account/region-level Cognito checks (run once per region).

    Input:
      account -- {
          '_region': str,
          '_pools': [ {'id', 'name', 'clientCount', 'idpCount', 'error'} ... ],
          '_listError': error code when list_user_pools failed (pool list incomplete)
      }
      'error' is an error code when the app clients or identity providers of a
      pool could not be fully listed (counts are then unreliable).
    """

    # A pool with exactly one app client and no external identity provider is
    # an isolated, single-application identity store ("silo"). Report when the
    # region holds at least this many of them.
    SILO_MIN_POOLS = 3

    def __init__(self, account):
        super().__init__()
        self.account = account
        self._resourceName = f"Account::{account.get('_region', 'unknown')}"
        pools = account.get('_pools') or []
        self.addII('userPoolCount', len(pools))

    def _checkCognitoPerAppIdentitySilos(self):
        key = 'cognitoPerAppIdentitySilos'
        pools = self.account.get('_pools') or []
        listError = self.account.get('_listError')
        if not pools:
            if listError:
                self.results[key] = [0, f"Unable to evaluate ({listError})"]
            else:
                self.results[key] = [0, "No user pools in this region"]
            return

        silos = [p for p in pools if not p.get('error')
                 and p.get('clientCount') == 1 and p.get('idpCount') == 0]
        errored = [p for p in pools if p.get('error')]
        names = ', '.join(sorted(p.get('name') or p.get('id') or '?' for p in silos)[:5])

        if len(silos) >= self.SILO_MIN_POOLS:
            self.results[key] = [
                -1, f"{len(silos)} of {len(pools)} user pools each serve a single app client with no "
                    f"federated identity provider ({names}{', ...' if len(silos) > 5 else ''})"
            ]
            return
        if listError:
            self.results[key] = [0, f"Unable to evaluate ({listError})"]
            return
        if errored and len(silos) + len(errored) >= self.SILO_MIN_POOLS:
            self.results[key] = [0, f"Unable to evaluate ({errored[0]['error']})"]
            return
        self.results[key] = [
            1, f"{len(silos)} single-app user pool(s) without federation out of {len(pools)} "
               f"(threshold {self.SILO_MIN_POOLS})"
        ]
