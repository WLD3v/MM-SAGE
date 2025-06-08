from helpers.file_helper import read_json

if __name__ == '__main__':
    teams = ['fox', 'harrison', 'russellmitchell', 'santos', 'shaw', 'wardbeck', 'wheeler', 'wilson']
    numbers = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']

    alerts = []
    for team in teams:
        alerts += read_json(f'../../output/team_alerts/{team}_alerts.json')

    # Remove benign alerts
    alerts = [alert for alert in alerts if alert['event_label'] != '-']

    alerts_dict = {}
    for alert in alerts:
        # Read variables from the json alert
        host = alert['host']
        ids = alert['ids']
        source = alert['source']
        label = alert['event_label']

        # Ensure the analysis dict has the needed keys
        if host not in alerts_dict.keys():
            alerts_dict[host] = {}

        if ids not in alerts_dict[host].keys():
            alerts_dict[host][ids] = {}

        if source not in alerts_dict[host][ids].keys():
            alerts_dict[host][ids][source] = {}

        if label not in alerts_dict[host][ids][source].keys():
            alerts_dict[host][ids][source][label] = []

        # Add data to the dict for analysis
        alerts_dict[host][ids][source][label].append(alert)

    alert_counter = 0
    for host in alerts_dict.keys():
        for ids in alerts_dict[host].keys():
            for source in alerts_dict[host][ids].keys():
                for label in alerts_dict[host][ids][source].keys():
                    count = len(alerts_dict[host][ids][source][label])
                    alert_counter += count
                    print(f'{host.replace('_', '\\_')} & {ids} & {source} & {label.replace('_', '\\_')} & {count} \\\\')

    assert len(alerts) >= alert_counter, 'Discarded labels during log analysis'
    assert len(alerts) <= alert_counter, 'Duplicated labels during log analysis'

    print(f'Read a total of {len(alerts)} alerts')
