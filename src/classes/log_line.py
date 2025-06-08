import datetime


class LogLine:
    def __init__(self, line_nr: int, timestamp: datetime.datetime, raw: str):
        self.line_nr = line_nr
        self.timestamp = timestamp
        self.raw = raw.replace('\n', '')
        self.labels = None
        self.host = None
        self.file = None

    def to_dict(self):
        return {
            'timestamp': self.timestamp.strftime("%Y-%m-%d %H:%M:%S.%f"),
            'labels': self.labels,

            'host': self.host,
            'file': self.file,

            'raw': self.raw,
        }
