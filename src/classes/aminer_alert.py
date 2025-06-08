from classes.alert import Alert
from datetime import datetime, timezone


class AMinerAlert(Alert):
    def __init__(self, alert: dict, ip_to_hostname: dict):
        assert len(alert['LogData']['Timestamps']) == 1, 'Unexpected amount of Timestamps'
        assert len(alert['LogData']['LogResources']) == 1, 'Unexpected amount of LogResources'

        self.timestamp = datetime.fromtimestamp(alert['LogData']['Timestamps'][0], timezone.utc)

        self.ids = 'aminer'
        self.host = ip_to_hostname[alert['AMiner']['ID']]
        self.file = alert['LogData']['LogResources'][0]
        self.signature = alert['AnalysisComponent']['AnalysisComponentName']

        # Remove redundant signature information
        if self.signature.startswith('AMiner: '):
            self.signature = self.signature[8:]

        self.host_ip = alert['AMiner']['ID']
        self.src_ip = None
        self.src_port = None
        self.dst_ip = None
        self.dst_port = None

        Alert.__init__(self)
