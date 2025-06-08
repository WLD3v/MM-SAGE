from classes.suricata_alert import SuricataAlert
from classes.wazuh_alert import WazuhAlert
from classes.aminer_alert import AMinerAlert
from helpers.file_helper import read_json_lines, write_json
from helpers.map_helper import event_code_to_source

import yaml
import time
import pandas as pd


def collect_hostname_to_ip_mapping(teams: list):
    hostname_to_ip = {}

    for team in teams:
        with open(f'../../input/AIT-LDS/{team}/processing/config/servers.yaml', 'r') as file:
            servers = yaml.safe_load(file)

        for hostname in servers.keys():
            if hostname not in hostname_to_ip.keys():
                hostname_to_ip[hostname] = servers[hostname]['default_ipv4_address']

    return hostname_to_ip


def collect_ip_to_hostname_mapping(teams: list):
    team_ip_to_hostname = {}

    for team in teams:
        ip_to_hostname = {}

        with open(f'../../input/AIT-LDS/{team}/processing/config/servers.yaml', 'r') as file:
            servers = yaml.safe_load(file)

        for hostname in servers.keys():
            ip_to_hostname[servers[hostname]['default_ipv4_address']] = hostname

        team_ip_to_hostname[team] = ip_to_hostname

    return team_ip_to_hostname


def collect_team_labels(teams: list):
    print('(1) COLLECTING LABELS')

    team_labels = {}

    for team in teams:
        labels_df = pd.read_csv(f'../../input/AIT-ADS/{team}/labels.csv')
        labels_df.columns = ['timestamp', 'signature', 'host_ip', 'host', 'event_code', 'time_label', 'event_label']
        labels_df['signature'] = labels_df['signature'].apply(remove_signature_prefix)

        team_labels[team] = labels_df

        print(f'[{team}] | Collected {len(labels_df)} labels')

    return team_labels


def remove_signature_prefix(signature: str):
    if signature.startswith('Suricata: Alert - '):
        return signature[18:]
    elif signature.startswith('Wazuh: '):
        return signature[7:]
    elif signature.startswith('AMiner: '):
        return signature[8:]

    return signature


def collect_team_alerts(teams: list, team_ip_to_hostname):
    print('\n(2) COLLECTING ALERTS')

    team_alerts = {}

    for team in teams:
        suricata_alerts, wazuh_alerts = collect_suricata_wazuh_alerts(team, team_ip_to_hostname[team])
        aminer_alerts = collect_aminer_alerts(team, team_ip_to_hostname[team])
        alerts = suricata_alerts + wazuh_alerts + aminer_alerts

        team_alerts[team] = alerts

        print(
            f'[{team}] | Collected {len(alerts)} total alerts from {len(suricata_alerts)} Suricata alerts, {len(wazuh_alerts)} Wazuh alerts and {len(aminer_alerts)} AMiner alerts')

    return team_alerts


def collect_suricata_wazuh_alerts(team: str, ip_to_hostname: dict):
    alerts = read_json_lines(f'../../input/AIT-ADS/{team}/wazuh.json')

    suricata_alerts = [SuricataAlert(alert, ip_to_hostname) for alert in alerts if 'suricata' in alert['rule']['groups']]
    wazuh_alerts = [WazuhAlert(alert, ip_to_hostname) for alert in alerts if not 'suricata' in alert['rule']['groups']]

    return suricata_alerts, wazuh_alerts


def collect_aminer_alerts(team: str, ip_to_hostname: dict):
    alerts = read_json_lines(f'../../input/AIT-ADS/{team}/aminer.json')

    aminer_alerts = [AMinerAlert(alert, ip_to_hostname) for alert in alerts]

    return aminer_alerts


def update_alerts(team_labels: dict, team_alerts: dict, team_ip_to_hostname: dict, hostname_to_ip: dict):
    print('\n(3) UPDATING ALERTS')

    for team in team_labels.keys():

        alerts = []
        for alert in team_alerts[team]:
            label = find_match(alert, team_labels[team])

            alert.source = event_code_to_source[label['event_code'].split('-')[1]]
            alert.event_code = label['event_code']
            alert.event_label = label['event_label']
            alert.time_label = label['time_label']

            # Replace scenario specific IP information with global IP information
            host_ip, _ = process_ip(alert.host_ip, None, hostname_to_ip, team_ip_to_hostname[team])
            src_ip, src_port = process_ip(alert.src_ip, alert.src_port, hostname_to_ip, team_ip_to_hostname[team])
            dst_ip, dst_port = process_ip(alert.dst_ip, alert.dst_port, hostname_to_ip, team_ip_to_hostname[team])

            alert.host_ip = host_ip
            alert.src_ip = src_ip
            alert.src_port = src_port
            alert.dst_ip = dst_ip
            alert.dst_port = dst_port

            alerts.append(alert)

        team_alerts[team] = alerts

        print(f'[{team}] | Labelled {len(team_alerts[team])} total alerts')

    return team_alerts


def find_match(alert, labels_df: pd.DataFrame):
    timestamp = alert.unix_timestamp()

    query = f'timestamp == {timestamp} & signature == "{alert.signature}" & host == "{alert.host}"'
    matches_df = labels_df.query(query)
    match_df = matches_df.drop_duplicates()

    assert len(match_df) != 0, "Alert matches with no label!"
    assert len(match_df) == 1, "Alert matches with multiple unique labels!"

    return match_df.iloc[0]


def process_ip(ip: str, port: str, hostname_to_ip: dict, ip_to_hostname: dict):
    # Standardise unknown IPs
    if ip is None or ip == 'unknown':
        ip = 'unknown'
        port = 'unknown'

    # Move port information from ip when possible
    elif len(ip.split(':')) == 2:
        port = ip.split(':')[1]
        ip = ip.split(':')[0]

    # Replace scenario specific IPs with global IPs where possible
    if ip in ip_to_hostname.keys():
        ip = hostname_to_ip[ip_to_hostname[ip]]

    return ip, port


def save_alerts(team_alerts: dict):
    directory = '../../output/team_alerts'

    for team in team_alerts.keys():
        path = f'{directory}/{team}_alerts.json'
        data = [alert.to_dict() for alert in team_alerts[team]]
        write_json(path, data)

    print(f'\nSaved results under {directory}')


if __name__ == '__main__':
    print('*** COLLECTING LOG ENTRIES ***')
    start_time = time.time()

    teams = ['fox', 'harrison', 'russellmitchell', 'santos', 'shaw', 'wardbeck', 'wheeler', 'wilson']

    # Create a global hostname-to-ip mapping
    hostname_to_ip = collect_hostname_to_ip_mapping(teams)

    # Create scenario specific ip-to-hostname mappings
    team_ip_to_hostname = collect_ip_to_hostname_mapping(teams)

    # Collect and combine the alerts and their labels
    team_labels = collect_team_labels(teams)
    team_alerts = collect_team_alerts(teams, team_ip_to_hostname)
    team_alerts = update_alerts(team_labels, team_alerts, team_ip_to_hostname, hostname_to_ip)

    save_alerts(team_alerts)

    print(f'\nSTAGE COMPLETED AFTER {round(time.time() - start_time)} SECONDS')
