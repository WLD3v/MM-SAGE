import os
import time

from datetime import datetime

from helpers.file_helper import read_json, write_json
from helpers.map_helper import alert_label_to_observable_label, log_labels_to_observable_label
from classes.observable import Observable

DUPLICATE_WINDOW = 1.0


def collect_observables(host: str, observable_duplicate_window: float):
    print('*** COLLECTING OBSERVABLES ***')
    start_time = time.time()

    # Collect, filter and parse various types of data into instances of a generic Observable class
    team_alerts = collect_alerts(host)
    team_logs = collect_logs(host)

    # Combine the various types of observables and sort them on time of observation
    team_observables = combine_observables(team_alerts, team_logs)

    # Filter out observables that are unlikely to be attack related
    team_observables = filter_observables(team_observables, observable_duplicate_window)

    # Save the observables to file for manual inspection
    save_observables(team_observables)

    print(f'\nSTAGE COMPLETED AFTER {round(time.time() - start_time)} SECONDS')

    return team_observables


def collect_alerts(host: str):
    team_alerts = {}

    directory = 'output/team_alerts'
    for file in os.listdir(directory):
        team = file.split('_')[0]

        alerts = read_json(f'{directory}/{file}')
        alerts = [alert for alert in alerts if alert['host'] == host]
        alerts = parse_alerts(alerts)

        team_alerts[team] = alerts

    return team_alerts


def parse_alerts(alerts: list):
    observables = []

    for alert in alerts:
        source = 'alerts'
        host = alert['host']
        timestamp = datetime.strptime(alert['timestamp'], '%Y-%m-%d %H:%M:%S.%f')
        category = alert_label_to_observable_label[alert['event_label']]
        description = alert['signature']
        detector = alert['event_code']

        observables.append(Observable(source, host, timestamp, category, description, detector))

    return observables


def collect_logs(host: str):
    team_logs = {}

    directory = 'output/team_logs'
    for file in os.listdir(directory):
        team = file.split('_')[0]

        logs = read_json(f'{directory}/{file}')
        logs = [log for log in logs if log['host'] == host]
        logs = parse_logs(logs)

        team_logs[team] = logs

    return team_logs


def parse_logs(logs: list):
    observables = []

    for log in logs:
        source = 'logs'
        host = log['host']
        timestamp = datetime.strptime(log['timestamp'], '%Y-%m-%d %H:%M:%S.%f')
        category = log_labels_to_observable_label['|'.join(log['labels'])]
        description = log['raw']
        detector = log['file']

        observables.append(Observable(source, host, timestamp, category, description, detector))

    return observables


def combine_observables(team_alerts: dict, team_logs: dict):
    team_observables = {}

    assert team_alerts.keys() == team_logs.keys(), 'Teams of alerts and logs do not align'

    for team in team_alerts.keys():
        observables = team_alerts[team] + team_logs[team]
        observables = sorted(observables, key=lambda observable: observable.timestamp)

        team_observables[team] = observables

        print(f'[{team}] Combined {len(team_alerts[team])} alerts and {len(team_logs[team])} logs into {len(observables)} observables')

    return team_observables


def filter_observables(team_observables: dict, observable_duplicate_window: float):
    for team, observables in team_observables.items():
        # Filter on non-benign, non-duplicate observables
        nb_observables = [observable for observable in observables if observable.category != '-']
        nb_nd_observables = [observable for index, observable in enumerate(nb_observables) if not observable.is_duplicate(observables[index - 1], observable_duplicate_window)]

        team_observables[team] = nb_nd_observables

        print(f'[{team}] Removed {len(observables) - len(nb_observables)} (likely) benign observables and {len(nb_observables) - len(nb_nd_observables)} duplicate observables')

    return team_observables


def save_observables(team_observables: dict):
    directory = 'output/team_observables'
    for team, observables in team_observables.items():
        path = f'{directory}/{team}_observables.json'
        data = [observable.to_dict() for observable in observables]
        write_json(path, data)

    print(f'\nSaved intermediate results under {directory}')
