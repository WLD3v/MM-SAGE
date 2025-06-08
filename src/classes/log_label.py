class LogLabel:
    def __init__(self, label):
        self.line_nr = label['line']
        self.labels = label['labels']
        self.rules = label['rules']
