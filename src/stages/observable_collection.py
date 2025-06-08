from analysis.log_analysis import Ruleset
from helpers.file_helper import write_json
from parsers.alert_parser import collect_observable_alerts
from parsers.log_parser import collect_observable_logs


def collect_observables(hosts: list, modalities: list, use_labels: bool, observable_duplicate_window: float, ruleset: Ruleset):
    team_observables = collect_from_modalities(hosts, modalities, use_labels, ruleset)
    team_observables = sort_observables(team_observables)
    team_observables = filter_observables(team_observables, observable_duplicate_window)

    save_observables(team_observables)

    return team_observables


def collect_from_modalities(hosts: list, modalities: list, use_labels: bool, ruleset: Ruleset):
    team_observables = {}

    # Collect and parse log entries
    if 'logs' in modalities:
        team_log_observables = collect_observable_logs(hosts, use_labels, ruleset)

        for team, observables in team_log_observables.items():
            if team not in team_observables.keys():
                team_observables[team] = []

            team_observables[team] += observables
            print(f'[{team}] Collected {len(observables)} observable logs')

    # Collect and parse alerts (when the related IDS is also provided in modalities)
    team_alert_observables = collect_observable_alerts(hosts, modalities, use_labels, ruleset)

    for team, observables in team_alert_observables.items():
        if team not in team_observables.keys():
            team_observables[team] = []

        team_observables[team] += observables
        print(f'[{team}] Collected {len(observables)} observable alerts')

    return team_observables


def sort_observables(team_observables: dict):
    for team, observables in team_observables.items():
        # Sort observables based on the provided timestamps
        team_observables[team] = sorted(observables, key=lambda observable: observable.timestamp)

    return team_observables


def filter_observables(team_observables: dict, observable_duplicate_window: float):
    for team, observables in team_observables.items():
        # Keep only non-benign observables
        nb_observables = [observable for observable in observables if observable.category != '-']

        # Keep only non-duplicate observables
        nb_nd_observables = [observable for index, observable in enumerate(nb_observables) if not observable.is_duplicate(observables[index - 1], observable_duplicate_window)]

        team_observables[team] = nb_nd_observables
        print(f'[{team}] Removed {len(observables) - len(nb_observables)} (likely) benign observables and {len(nb_observables) - len(nb_nd_observables)} duplicate observables')

    return team_observables


def save_observables(team_observables: dict):
    for team, observables in team_observables.items():
        path = f'output/observables/{team}_observables.json'
        data = [observable.to_dict() for observable in observables]
        write_json(path, data)

    print('\nSaved observables under output/observables')
