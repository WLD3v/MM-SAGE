from classes.alert import Alert
from helpers.file_helper import read_dict_value

from datetime import datetime, timezone


class WazuhAlert(Alert):
    def __init__(self, alert: dict, ip_to_hostname: dict):
        self.timestamp = datetime.strptime(alert['@timestamp'], "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)

        self.ids = 'wazuh'
        self.host = ip_to_hostname[alert['agent']['ip']]
        self.file = alert['location']
        self.signature = alert['rule']['description']

        self.host_ip = alert['agent']['ip']
        self.src_ip = read_dict_value(alert, ['data', 'srcip'], 'unknown')
        self.src_port = read_dict_value(alert, ['data', 'srcport'], 'unknown')
        self.dst_ip = read_dict_value(alert, ['data', 'dstip'], 'unknown')
        self.dst_port = read_dict_value(alert, ['data', 'dstport'], 'unknown')

        Alert.__init__(self)
