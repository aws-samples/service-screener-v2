import copy
import traceback
import botocore
import time
import os
import math
import csv
import threading

import concurrent.futures as cf

from utils.Config import Config
from utils.Checkpoint import Checkpoint
from utils.Tools import _warn, _info
from utils.CustomPage.CustomPage import CustomPage
import constants as _C

# Guards concurrent appends to the slow-checks log file.
_slow_log_lock = threading.Lock()

# Guards creation of per-key locks for Evaluator._memo / _sharedMemo.
_memo_init_lock = threading.Lock()


_TRANSIENT_ERROR_CODES = frozenset((
    'Throttling', 'ThrottlingException', 'ThrottledException', 'TooManyRequestsException',
    'RequestLimitExceeded', 'RequestThrottled', 'RequestThrottledException', 'SlowDown',
    'ProvisionedThroughputExceededException', 'ServiceUnavailable', 'ServiceUnavailableException',
    'InternalError', 'InternalFailure', 'InternalServerError', 'InternalServerException',
))


def _isTransient(e):
    """Errors a later retry may not hit: never cache them, so one throttled
    call does not become 'unable to evaluate' for every later check."""
    if isinstance(e, (botocore.exceptions.ConnectionError, botocore.exceptions.ReadTimeoutError,
                      botocore.exceptions.ConnectTimeoutError)):
        return True
    if isinstance(e, botocore.exceptions.ClientError):
        err = e.response.get('Error', {}) or {}
        status = (e.response.get('ResponseMetadata', {}) or {}).get('HTTPStatusCode') or 0
        return err.get('Code') in _TRANSIENT_ERROR_CODES or status >= 500 or status == 429
    return False


def _memoFetch(store, lock, key, fn):
    with lock:
        if key not in store:
            try:
                store[key] = (True, fn())
            except Exception as e:
                if _isTransient(e):
                    raise            # not cached: the next caller retries
                store[key] = (False, e)  # cached and re-raised to every caller
    ok, value = store[key]
    if ok:
        # Each caller gets its own copy: some checks modify what they read.
        return copy.deepcopy(value)
    raise value


def _log_slow_check(tmp_obj, method_name, timeSpent):
    """Append a row to the per-run slow_checks.log if configured.

    Called whenever a check takes >= 3s. Best-effort — never raises.
    Row format: service,resource,check,duration_s
    """
    log_path = Config.get('slow_log_path')
    if not log_path:
        return
    try:
        service = type(tmp_obj).__name__
        resource = getattr(tmp_obj, '_resourceName', '') or ''
        with _slow_log_lock:
            with open(log_path, 'a', encoding='utf-8', newline='') as f:
                csv.writer(f).writerow([service, resource, method_name, timeSpent])
    except Exception:
        # Never let logging break a scan.
        pass  # nosec B110


def runSingleCheck(tmp_obj, method_name):
    debugFlag = Config.get('DEBUG')
    obj = tmp_obj
    try:
        startTime = time.time()
        getattr(obj, method_name)()
        timeSpent = round(time.time() - startTime, 3)
        if debugFlag:
            print('--- --- fn: ' + method_name)
            if timeSpent >= 0.2:
                _warn("Long running checks {}s".format(timeSpent))
        elif timeSpent >= 3:
            _warn("[Slow] {} took {}s".format(method_name, timeSpent))

        if timeSpent >= 3:
            _log_slow_check(tmp_obj, method_name, timeSpent)

        return 'OK'
    except botocore.exceptions.ClientError as e:
        code = e.response['Error']['Code']
        msg = e.response['Error']['Message']
        print(code, msg)
        emsg = traceback.format_exc()
    except Exception:
        emsg = traceback.format_exc()

    print(emsg)
    return emsg

class Evaluator():
    def __init__(self):
        self.init()
        
    def init(self):
        self.results = {}
        self.InventoryInfo = {}
        self.chartData = {}
        self.classname = type(self).__name__
    
    # ------------------------------------------------------------------ #
    # Read-once caches for API responses shared by several _check methods.
    # Checks of one driver run concurrently (see run()), so both helpers are
    # thread-safe and fetch at most once. A raised exception is cached and
    # re-raised to every caller, so each check handles errors exactly as if
    # it had made the call itself.
    # ------------------------------------------------------------------ #
    def _memo(self, key, fn):
        """Per-resource cache: fn() runs at most once per driver instance."""
        with _memo_init_lock:
            if not hasattr(self, '_memoStore'):
                self._memoStore = {}
                self._memoLocks = {}
            lock = self._memoLocks.setdefault(key, threading.Lock())
        return _memoFetch(self._memoStore, lock, key, fn)

    def _sharedMemo(self, key, fn):
        """Cache shared by every driver instance in this scan, for account- or
        region-level data that does not depend on the resource. Include the
        region (and anything else that changes the answer) in `key`. Cleared by
        Config.init()."""
        store = Config.get('__sharedMemo', None)
        if not isinstance(store, dict):
            with _memo_init_lock:
                store = Config.get('__sharedMemo', None)
                if not isinstance(store, dict):
                    store = {'values': {}, 'locks': {}}
                    Config.set('__sharedMemo', store)
        acct = (Config.get('stsInfo', {}) or {}).get('Account', 'default')
        fullKey = (acct, key)
        with _memo_init_lock:
            lock = store['locks'].setdefault(fullKey, threading.Lock())
        return _memoFetch(store['values'], lock, fullKey, fn)

    def addII(self, k, v):
        self.InventoryInfo[k] = v
        
    def getII(self, k):
        if k in self.InventoryInfo:
            return self.InventoryInfo[k]
        else:
            _warn("{} is not found in drivers/{}.InventoryInfo".format(k, self.classname), forcePrint=False)
            return None

    def setChartData(self, title: str, category: str, data: int):
        if title not in self.chartData:
            self.chartData[title] = {category: data}
        else:
            self.chartData[title][category] = data
            
    def getChartData(self):
        return self.chartData

    def run(self, serviceName):
        servClass = self.classname
        rulePrefix = serviceName.__name__ + '::rules'
        servMethods = servClass + '::methods'
        rules = Config.get(rulePrefix, [])

        debugFlag = Config.get('DEBUG')

        checkpointAcct = (Config.get('stsInfo', {}) or {}).get('Account', 'default')
        checkpointRegion = Config.get('CURRENT_REGION', 'unknown')
        checkpointResourceId = getattr(self, '_resourceName', None)

        if checkpointResourceId is not None and Checkpoint.isDone(
            checkpointAcct, serviceName.__name__, checkpointRegion, servClass, checkpointResourceId
        ):
            cached = Checkpoint.getCached(
                checkpointAcct, serviceName.__name__, checkpointRegion, servClass, checkpointResourceId
            ) or {}
            self.results = cached.get('results', {})
            self.InventoryInfo = cached.get('info', {})

            scannedKey = 'scanned_' + serviceName.__name__.lower()
            scanned = Config.get(scannedKey)
            Config.set(scannedKey, {
                'resources': scanned['resources'] + 1,
                'rules': scanned['rules'],
                'exceptions': scanned['exceptions']
            })
            return

        ecnt = cnt = 0
        emsg = []

        #Improve of methods scanning
        methods = Config.get(servMethods, [])
        if methods == []:
            methods = [method for method in dir(self) if method.startswith('__') is False and method.startswith('_check') is True]
            Config.set(servMethods, methods)

        filteredMethods = [method for method in methods if not rules or method[6:].lower() in rules]

        cnt = len(filteredMethods)

        # Use concurrent execution by default for better performance
        # Fall back to sequential if explicitly requested via --sequential flag
        use_sequential = Config.get('sequential', False)
        
        if use_sequential:
            # Sequential execution (for debugging or compatibility)
            for method in methods:
                if not rules or str.lower(method[6:]) in rules:
                    try:
                        
                        startTime = time.time()
                        if debugFlag:
                            print('--- --- fn: ' + method)
                            
                        getattr(self, method)()
                        timeSpent = round(time.time() - startTime, 3)
                        if debugFlag:
                            if timeSpent >= 0.2:
                                _warn("Long running checks {}s".format(timeSpent))
                        elif timeSpent >= 3:
                            _warn("[Slow] {} took {}s".format(method, timeSpent))

                        if timeSpent >= 3:
                            _log_slow_check(self, method, timeSpent)
                        
                    except botocore.exceptions.ClientError as e:
                        code = e.response['Error']['Code']
                        msg = e.response['Error']['Message']
                        print(code, msg)
                        print(traceback.format_exc())
                        emsg.append(traceback.format_exc())
                    except Exception:
                        ecnt += 1
                        print(traceback.format_exc())
                        emsg.append(traceback.format_exc())
        else:
            # Concurrent execution (default for better performance)
            with cf.ThreadPoolExecutor() as executor:
                futures = [executor.submit(runSingleCheck, self, method) for method in filteredMethods]
                
                for future in cf.as_completed(futures):
                    if future.result() == 'OK':
                        continue
                    else:
                        emsg.append(future.result())
                        ecnt += 1
            
        if emsg:
            with open(_C.FORK_DIR + '/error.txt', 'a+') as f:
                f.write('\n\n'.join(emsg))
                f.close()

        if checkpointResourceId is not None:
            Checkpoint.markDone(
                checkpointAcct, serviceName.__name__, checkpointRegion, servClass,
                checkpointResourceId, self.results, self.InventoryInfo
            )

        scannedKey = 'scanned_'+serviceName.__name__.lower()
        # print(scannedKey)
        
        scanned = Config.get(scannedKey)
        Config.set(scannedKey, {
            'resources': scanned['resources'] + 1,
            'rules': scanned['rules'] + cnt,
            'exceptions': scanned['exceptions'] + ecnt
        })
        
        if debugFlag:
            self.showInfo()
            print()
        
    def showInfo(self):
        print("Class: {}".format(self.classname))
        print(self.getInfo())
        # __pr(self.getInfo())
        
    def getInfo(self):
        return {'results': self.results, 'info': self.InventoryInfo}
    
    ## Enhancement 20240117 - Capture all scanned resources    
    def __del__(self):
        try:
            driver = type(self).__name__.lower()
            classPrefix = Config.getDriversClassPrefix(driver)
            
            ConfigKey = 'AllScannedResources.' + classPrefix
            scanned = Config.get(ConfigKey, [])
            
            # print(classPrefix, Config.get(classPrefix))
            
            hasError = '1'
            for check, find in self.results.items():
                if find[0] == -1:
                    hasError = '-1'
                    break
            
            name = ""
            if hasattr(self, '_resourceName'):
                name = self._resourceName
            else:
                _warn("driver: '{}' need to set self._resourceName".format(driver))

            # Ensure all values are strings and handle None values
            config_value = Config.get(classPrefix, "") or ""
            driver_value = driver or ""
            name_value = name or ""
            error_value = hasError or ""
            
            # Join with proper string values
            scanned.append(';'.join([config_value, driver_value, name_value, error_value]))
            Config.set(ConfigKey, scanned)
                
            ## Handle custom page requirement
            cp = CustomPage()
        except Exception as e:
            # Prevent destructor errors from propagating
            try:
                _warn(f"Error in Evaluator destructor for {type(self).__name__}: {str(e)}")
            except:
                # If even logging fails, silently ignore to prevent cascade errors
                pass
        
        emsg = []
        try:
            cp.trackInfo(driver, name, self.results, self.InventoryInfo)
        except Exception:
            print(traceback.format_exc())
            emsg.append(traceback.format_exc())
        
        if emsg:
            with open(_C.FORK_DIR + '/error.txt', 'a+') as f:
                f.write('\n\n'.join(emsg))
                f.close()
        