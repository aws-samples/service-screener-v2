import re
from collections import defaultdict

from services.PageBuilder import PageBuilder
from utils.Tools import _warn

class GuarddutypageBuilder(PageBuilder):
    DATASOURCE = [
        'FlowLogs', 'CloudTrail', 'DnsLogs', 'S3Logs', ['Kubernetes', 'AuditLogs'],
        ['MalwareProtection', 'ScanEc2InstanceWithFindings']
    ]
    SERVICESUMMARY_DEFAULT = {
        'EC2': 0,
        'IAMUser': 0,
        'Kubernetes': 0,
        'S3': 0,
        'Malware': 0,
        'RDS': 0
    }

    def __init__(self, service, reporter):
        super().__init__(service, reporter)
        
        self.template = 'default'
        self.statSummary = {}
        self.findings = []
        self.findingsLink = {}
        self.settings = {}
        self._gdProcess()

    def _gdProcess(self):
        self.statSummary = {'services': self.SERVICESUMMARY_DEFAULT}

        detail = self.reporter.getDetail()
        for region, detectors in detail.items():
            findings = ''
            for detectorId, detector in detectors.items():
                if 'Findings' in detector:
                    findings = self._gdProcessFinding(detector['Findings']['value'])
                
                ustat = '-1'
                if 'UsageStat' in detector and 'value' in detector['UsageStat']:
                    ustat = detector['UsageStat']['value']
                
                ftrial = '-1'
                if 'FreeTrial' in detector and 'value' in detector['FreeTrial']:
                    ftrial = detector['FreeTrial']['value']
                
                settings = '-1'
                if 'Settings' in detector and 'value' in detector['Settings'] and 'Settings' in detector['Settings']['value']:
                    settings = detector['Settings']['value']['Settings']
                    
                self.settings[region] = self._gdProcessGeneral(ftrial, settings, ustat)

            if findings:
                self.findings.append(findings['detail'])

                self.statSummary[region] = findings['stat']['severity']
                for serv, val in findings['stat']['services'].items():
                    if not serv in self.statSummary['services']:
                        _warn("New GuardDuty category not being tracked (summary), please submit an issue to github --> " + serv)
                        self.statSummary['services'][serv] = 0
                    
                    self.statSummary['services'][serv] += val

    def _gdProcessFinding(self, findings):
        if not findings:
            return
        
        arr = {
            'stat': {
                'severity': {},
                'services': self.SERVICESUMMARY_DEFAULT.copy()
            }
        }

        findings_by_severity = {'8': defaultdict(list), '5': defaultdict(list), '2': defaultdict(list)}

        high = len(findings['8']) if '8' in findings else 0
        medium = len(findings['5']) if '5' in findings else 0
        low = len(findings['2']) if '2' in findings else 0

        arr['stat']['severity'] = {
            'HIGH': high,
            'MEDIUM': medium,
            'LOW': low
        }

        severity_modes = ['8', '5', '2']
        patterns = r"\w+"
        for severity in severity_modes:
            if severity not in findings:
                continue

            for topic, detail in findings[severity].items():
                result = re.findall(patterns, topic)
                service_type = result[1]

                if result[0] == 'Execution':
                    service_type = 'Malware'
                
                if not service_type in findings_by_severity[severity]:
                    findings_by_severity[severity][service_type] = {}
                    
                findings_by_severity[severity][service_type][topic] = detail['res_']
                self.findingsLink[service_type+topic] = detail['__']

            for service, detail in findings_by_severity[severity].items():
                if not service in arr['stat']['services']:
                    _warn("New GuardDuty category not being tracked (detail), please submit an issue to github --> " + service)
                    arr['stat']['services'][service] = 0
                
                arr['stat']['services'][service] += len(findings_by_severity[severity][service])

        arr['detail'] = findings_by_severity
        return arr

    def _gdProcessGeneral(self, free_trial, settings, usage_stat):
        empty_array = {
            'FreeTrial': -1,
            'Enabled': None,
            'Usage': 0
        }
        MAPPED = {
            'FLOW_LOGS': 'FlowLogs',
            'CLOUD_TRAIL': 'CloudTrail',
            'DNS_LOGS': 'DnsLogs',
            'S3_LOGS': 'S3Logs',
            'KUBERNETES_AUDIT_LOGS': 'Kubernetes:AuditLogs',
            'EC2_MALWARE_SCAN': 'MalwareProtection:ScanEc2InstanceWithFindings'
        }
        
        print('Free Trial =============')
        print(free_trial)
        print('Settings =============')
        print(settings)
        print('Usage =============')
        print(usage_stat)
        
        arr = {}
        for ds in self.DATASOURCE:
            if isinstance(ds, list):
                key = ds[0] + ':' + ds[1]
                arr[key] = empty_array.copy()

                ft = None
                if ds[0] in free_trial and ds[1] in free_trial[ds[0]] and 'FreeTrialDaysRemaining' in free_trial[ds[0]][ds[1]]:
                    ft = free_trial[ds[0]][ds[1]]['FreeTrialDaysRemaining']
                
                arr[key]['FreeTrial'] = ft if ft else 'N/A'

                estat = 'X'
                if ds[0] in settings and ds[1] in settings[ds[0]]:
                    _settings = settings[ds[0]][ds[1]]
                    
                    if ds[0] == 'MalwareProtection':
                        estat = _settings['EbsVolumes']['Status']
                    else:
                        estat = _settings['Status']
                
                arr[key]['Enabled'] = self._generate_enabled_icon(estat)

            else:
                arr[ds] = empty_array.copy()
                arr[ds]['FreeTrial'] = free_trial[ds]['FreeTrialDaysRemaining'] if free_trial[ds]['FreeTrialDaysRemaining'] else 'N/A'

                ds_name = ds if ds != 'DnsLogs' else 'DNSLogs'
                arr[ds]['Enabled'] = self._generate_enabled_icon(settings[ds_name]['Status'])

        total = 0
        for stat in usage_stat:
            amount = 0
            if 'Total' in stat and 'Amount' in stat['Total']:
                amount = round(float(stat['Total']['Amount']), 4)
                ds = MAPPED[stat['DataSource']]
                arr[ds]['Usage'] = amount
            
            total += amount

        arr['Total'] = total
        return arr
    
    def _generate_enabled_icon(self, status):
        icon = 'check-circle' if status == 'ENABLED' else 'ban'
        return f"<i class='nav-icon fas fa-{icon}'></i>"
    
    def buildContentSummary(self):
        output = []
    
        # Summary Row
        data_sets = {}
        labels = ['HIGH', 'MEDIUM', 'LOW']
        for region, stat in self.statSummary.items():
            if region == 'services':
                continue
    
            data_sets[region] = list(stat.values())
    
        html = self.generateBarChart(labels, data_sets)
        card = self.generateCard(self.getHtmlId('hmlStackedChart'), html, cardClass='warning', title='By Criticality', collapse=True)
        items = [[card, '']]
    
        html = self.generateDonutPieChart(self.statSummary['services'], 'servDoughnut')
        card = self.generateCard(self.getHtmlId('servChart'), html, cardClass='warning', title='By Category', collapse=True)
        items.append([card, ''])
    
        output.append(self.generateRowWithCol(6, items, "data-context='gdReport'"))
    
        # Usage/Settings Table
        tab = [
            "<table class='table table-sm'>",
            "<thead><tr><th>Region</th>"
        ]
    
        for ds in self.DATASOURCE:
            if isinstance(ds, list):
                ds = ':'.join(ds)
            tab.append("<th>{}</th>".format(ds.replace(':', '<br>')))
    
        tab.append("<th>Total</th>")
        tab.append("</tr></thead>")
        tab.append("<tbody><tr>")
    
        for region, o in self.settings.items():
            tab.append("<tr>")
            tab.append("<td>{}</td>".format(region))
    
            for ds in self.DATASOURCE:
                if isinstance(ds, list):
                    ds = ':'.join(ds)
    
                msg = "-"
                if ds in o:
                    d = o[ds]
                    
                    ftrial = d['FreeTrial']
                    if ftrial == 'N/A':
                        d['FreeTrial'] = 0
                    
                    has_trial = "({}D)".format(d['FreeTrial']) if float(d['FreeTrial']) > 0 else ""
                    msg = "{} ${:.4f}{}".format(d['Enabled'], d['Usage'], has_trial)
    
                tab.append("<td>{}</td>".format(msg))
    
            tab.append("<td><b>${}</b></td>".format(o['Total']))
            tab.append("</tr>")
    
        tab.append("</tbody>")
        tab.append("</table>")
    
        html = ''.join(tab)
        card = self.generateCard(self.getHtmlId('settingTable'), html, cardClass='info', title='Current Settings', collapse=True)
        items = [[card, '']]
    
        output.append(self.generateRowWithCol(12, items, "data-context='settingTable'"))
    
        return output
    
    def buildContentDetail(self):
        output = []
        _h = []
        _m = []
        _l = []
        for idx, f in enumerate(self.findings):
            if f['8'] is not None:
                _h.append(f['8'])
            if f['5'] is not None:
                _m.append(f['5'])
            if f['2'] is not None:
                _l.append(f['2'])
        
        # out = self.__groupFindings(__h)
        tab = []
        if _h:
            tab.append(self._buildFindingsList('High Severity', _h))
        if _m:
            tab.append(self._buildFindingsList('Medium Severity', _m))
        if _l:
            tab.append(self._buildFindingsList('Low Severity', _l))
        
        # tab.append(self.__buildFindingsList(title, items))
        html = 'No findings'
        if tab:
            html = ''.join(tab)
            del tab
        
        items = []
        card = self.generateCard(pid=self.getHtmlId('findings'), html=html, cardClass='alert', title='All findings', titleBadge='', collapse=True, noPadding=False)
        items.append([card, ''])
        
        output.append(self.generateRowWithCol(size=12, items=items, rowHtmlAttr="data-context='findings'"))
        return output



    def _groupFindings(self, items):
        results = {}
        for group, o in enumerate(items):
            for serv, item in o.items():
                if serv not in results:
                    results[serv] = {}
                for topic, detail in item.items():
                    if topic not in results[serv]:
                        results[serv][topic] = {'items': []}
                        
                    for idx, det in enumerate(detail):
                        results[serv][topic]['items'].append(det)
        return results
    
    
    def _buildFindingsList(self, title, items):
        out = self._groupFindings(items)
        tab = []
        tab.append("<h3>{}</h3>".format(title))
    
        for serv, det in out.items():
            # print(self.findingsLink[serv+det])
            
            cnt = 0
            tab.append("<ul><li>{}".format(serv))
            for topic, arrayItem in det.items():
                tab.append("<ul><li><a href='{}' target=_blank rel='noopener noreferrer'>{}</a><ul>".format(self.findingsLink[serv+topic], topic))
                for it in arrayItem['items']:
                    tab.append("<li>{}: ({}), {} | <small>{}</small></li>".format(it['region'], it['Count'], it['Title'], it['Id']))
                tab.append("</ul>") #findings
                tab.append("</li></ul>") #topic
            tab.append("</li></ul>") #Service
        return ''.join(tab)
