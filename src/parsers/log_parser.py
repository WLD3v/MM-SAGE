import os

from analysis.log_analysis import match_line, Ruleset
from classes.observable import Observable
from helpers.file_helper import read_json
from helpers.map_helper import log_labels_to_observable_label

from datetime import datetime

ATTACKER_ACCOUNTS = ['phopkins', 'jward', 'jhall', 'gmorgan', 'gmarsh', 'blord', 'kford', 'jwilkinson']


def collect_observable_logs(hosts: list, use_labels: bool, ruleset: Ruleset):
    team_observables = {}

    for file in os.listdir('output/logs'):
        team = file.split('_')[0]

        logs = read_json(f'output/logs/{file}')
        logs = [log for log in logs if log['host'] in hosts]
        observables = parse_to_observables(logs, use_labels, ruleset)

        team_observables[team] = observables

    return team_observables


def parse_to_observables(logs: list, use_labels: bool, ruleset: Ruleset):
    observables = []

    for log in logs:
        source = f'logs-{log['file']}'
        host = log['host']
        timestamp = datetime.strptime(log['timestamp'], '%Y-%m-%d %H:%M:%S.%f')

        # Use either the ground truth labels or the mapping creating manually with the help of log_analysis.py
        if use_labels:
            category = log_labels_to_observable_label['|'.join(log['labels'])]
        else:
            category = match_line(log['raw'], ruleset)[0]

        description = log['raw']
        label = log_labels_to_observable_label['|'.join(log['labels'])]
        detector = log['file']

        observable = Observable(source, host, timestamp, category, label, description, detector)
        observables.append(observable)

    return observables