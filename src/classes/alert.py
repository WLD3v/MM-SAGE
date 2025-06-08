from datetime import datetime, timezone


class Alert:
    def __init__(self):
        # Also contains fields defined in suricata_alert.py, wazuh_alert.py or aminer_alert.py
        self.timestamp = self.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")  # (i.e 2022-01-19 18:58:58.607)
        self.source = None  # (i.e syslogs)
        self.event_code = None  # (i.e W-Sys-Cav)
        self.event_label = None  # (i.e wpscan)
        self.time_label = None  # (i.e wpscan)

    def unix_timestamp(self):
        timestamp = datetime.strptime(self.timestamp, '%Y-%m-%d %H:%M:%S.%f')
        timestamp = timestamp.replace(tzinfo=timezone.utc)
        timestamp = int(timestamp.timestamp())

        return timestamp

    def to_dict(self):
        return {
            'timestamp': self.timestamp,
            'ids': self.ids,
            'source': self.source,
            'file': self.file,
            'signature': self.signature,
            'event_code': self.event_code,
            'host': self.host,
            'host_ip': self.host_ip,
            'src_ip': self.src_ip,
            'src_port': self.src_port,
            'dst_ip': self.dst_ip,
            'dst_port': self.dst_port,
            'event_label': self.event_label,
            'time_label': self.time_label
        }
