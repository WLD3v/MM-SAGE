import os

from analysis.log_analysis import Ruleset
from analysis.alert_analysis import match_alert
from classes.observable import Observable
from helpers.file_helper import read_json
from helpers.map_helper import alert_label_to_observable_label

from datetime import datetime


def collect_observable_alerts(hosts: list, modalities: list, use_labels: bool, ruleset: Ruleset):
    team_observables = {}

    for file in os.listdir('output/alerts'):
        team = file.split('_')[0]

        alerts = read_json(f'output/alerts/{file}')
        alerts = [alert for alert in alerts if alert['host'] in hosts]
        alerts = [alert for alert in alerts if alert['ids'] in modalities]
        observables = parse_to_observables(alerts, use_labels, ruleset)

        team_observables[team] = observables

    return team_observables


def parse_to_observables(alerts: list, use_labels: bool, ruleset: Ruleset):
    observables = []

    for alert in alerts:
        source = f'alerts-{alert['ids']}'
        host = alert['host']
        timestamp = datetime.strptime(alert['timestamp'], '%Y-%m-%d %H:%M:%S.%f')

        # Use either the ground truth labels or the mapping creating manually with the help of log_analysis.py
        if use_labels:
            category = alert_label_to_observable_label[alert['event_label']]
        else:
            category = match_alert(alert, ruleset)[0]

        description = alert['signature']
        label = alert_label_to_observable_label[alert['event_label']]
        detector = alert['event_code']

        observable = Observable(source, host, timestamp, category, label, description, detector)
        observables.append(observable)

    return observables
