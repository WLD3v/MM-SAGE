import datetime


class Observable:
    def __init__(self, source: str, host: str, timestamp: datetime.datetime, category: str, label: str, description: str, detector: str):
        # Where was the observation observed?
        self.source = source
        self.host = host
        self.detector = detector

        # When was the observation observed?
        self.timestamp = timestamp

        # What kind of observation is it?
        self.category = category
        self.label = label
        self.description = description

    def is_duplicate(self, observable, duplicate_window: float):
        # Observables are considered not duplicate when there is no comparable previous observable
        if observable is None:
            return False

        # Observables outside the duplicate window are not considered duplicates
        if abs(self.timestamp - observable.timestamp) >= datetime.timedelta(seconds=duplicate_window):
            return False

        # Observables inside the duplicate window with identical sources and descriptions are considered duplicates
        return self.source == observable.source and self.description == observable.description

    def to_dict(self):
        return {
            'source': self.source,
            'host': self.host,
            'detector': self.detector,
            'timestamp': self.timestamp.strftime('%Y-%m-%d %H:%M:%S.%f'),
            'category': self.category,
            'label': self.label,
            'description': self.description
        }
