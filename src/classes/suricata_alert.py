from classes.alert import Alert
from datetime import datetime, timezone


class SuricataAlert(Alert):
    def __init__(self, alert: dict, ip_to_hostname: dict):
        self.timestamp = datetime.strptime(alert['@timestamp'], "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)

        self.ids = 'suricata'
        self.host = ip_to_hostname[alert['agent']['ip']]
        self.file = alert['location']
        self.signature = alert['data']['alert']['signature']

        self.host_ip = alert['agent']['ip']
        self.src_ip = alert['data']['src_ip']
        self.src_port = alert['data']['src_port']
        self.dst_ip = alert['data']['dest_ip']
        self.dst_port = alert['data']['dest_port']

        Alert.__init__(self)
