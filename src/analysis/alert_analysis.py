import os

from helpers.analysis_helper import print_precision_recall
from helpers.file_helper import read_json
from analysis.log_analysis import Ruleset


def collect_alerts(host: str):
    team_alerts = {}

    for file in os.listdir('../../output/alerts'):
        team = file.split('_')[0]

        alerts = read_json(f'../../output/alerts/{file}')

        team_alerts[team] = {}
        team_alerts[team]['wazuh'] = [alert for alert in alerts if (alert['host'] == host and alert['ids'] == 'wazuh')]
        team_alerts[team]['suricata'] = [alert for alert in alerts if (alert['host'] == host and alert['ids'] == 'suricata')]
        team_alerts[team]['aminer'] = [alert for alert in alerts if (alert['host'] == host and alert['ids'] == 'aminer')]

    return team_alerts


def print_label_overview(team_alerts: dict, ids: str):
    labels_dict = {}

    for team in team_alerts.keys():
        for alert in team_alerts[team][ids]:
            if alert['event_label'] not in labels_dict:
                labels_dict[alert['event_label']] = {}

            if alert['signature'] not in labels_dict[alert['event_label']]:
                labels_dict[alert['event_label']][alert['signature']] = 0

            labels_dict[alert['event_label']][alert['signature']] += 1

    print(labels_dict)


def match_alert(alert: dict, ruleset: Ruleset):
    labels = []

    if matches_service_scan(alert, ruleset): labels.append('service_scan')
    if matches_dirb(alert, ruleset): labels.append('dirb')
    if matches_wpscan(alert, ruleset): labels.append('wpscan')
    if matches_webshell_cmd(alert, ruleset): labels.append('webshell_cmd')
    if matches_online_cracking(alert, ruleset): labels.append('online_cracking')
    if matches_attacker_change_user(alert, ruleset): labels.append('attacker_change_user')
    if matches_escalated_sudo_command(alert, ruleset): labels.append('escalated_sudo_command')

    assert len(labels) <= 1, f'Found multiple matching labels {labels} for alert: {alert}'

    if len(labels) == 0: return ['-']

    return labels


def matches_service_scan(alert: dict, ruleset: Ruleset):
    if ruleset == Ruleset.STRICT or ruleset == Ruleset.LENIENT or ruleset == Ruleset.LAX:
        # Suricata rules
        if alert['signature'] == 'ET SCAN Possible Nmap User-Agent Observed': return True

    return False


def matches_dirb(alert: dict, ruleset: Ruleset):
    if ruleset == Ruleset.STRICT or ruleset == Ruleset.LENIENT or ruleset == Ruleset.LAX:
        # Wazuh rules
        if alert['signature'] == 'Common web attack.': return True

    if ruleset == Ruleset.LENIENT or ruleset == Ruleset.LAX:
        # Wazuh rules
        if alert['signature'] == 'Apache: Attempt to access forbidden directory index.': return True
        if alert['signature'] == 'Apache: Attempt to access forbidden file or directory.': return True
        if alert['signature'] == 'Suspicious URL access.': return True

    if ruleset == Ruleset.LAX:
        # Wazuh rules
        if alert['signature'] == 'Web server 400 error code.': return True
        if alert['signature'] == 'Multiple web server 400 error codes from same source ip.': return True

        # AMiner rules
        if alert['signature'] == 'New status code in Apache Access log.': return True
        if alert['signature'] == 'New characters in Apache Access request.': return True
        if alert['signature'] == 'New event type.': return True
        if alert['signature'] == 'Unusual occurrence frequencies of Apache Access request methods.': return True
        if alert['signature'] == 'Unusual occurrence frequencies of Apache Access logs.': return True

    return False


def matches_wpscan(alert: dict, ruleset: Ruleset):
    if ruleset == Ruleset.STRICT or ruleset == Ruleset.LENIENT or ruleset == Ruleset.LAX:
        # Wazuh rules
        if alert['signature'] == 'CMS (WordPress or Joomla) brute force attempt.': return True

    if ruleset == Ruleset.LENIENT or ruleset == Ruleset.LAX:
        # Wazuh rules
        if alert['signature'] == 'CMS (WordPress or Joomla) login attempt.': return True

        # AMiner rules
        if alert['signature'] == 'New request method in Apache Access log.': return True

    if ruleset == Ruleset.LAX:
        # Wazuh rules
        if alert['signature'] == 'Web server 500 error code (Internal Error).': return True

    return False


def matches_webshell_cmd(alert: dict, ruleset: Ruleset):
    if ruleset == Ruleset.LAX:
        if alert['signature'] == 'High entropy in Apache Access request.': return True

    return False


def matches_online_cracking(alert: dict, ruleset: Ruleset):
    if ruleset == Ruleset.LAX:
        # Suricata rules
        if alert['signature'] == 'SURICATA HTTP unable to match response to request': return True

    return False


def matches_attacker_change_user(alert: dict, ruleset: Ruleset):
    if ruleset == Ruleset.STRICT or ruleset == Ruleset.LENIENT or ruleset == Ruleset.LAX:
        # Wazuh rules
        if alert['signature'] == 'User successfully changed UID.': return True

        # AMiner rules
        if alert['signature'] == 'New user_auth parameter combination in Audit logs.': return True

    if ruleset == Ruleset.LAX:
        # Aminer rules
        if alert['signature'] == 'New user_acct parameter combination in Audit logs.': return True
        if alert['signature'] == 'New cred_acq parameter combination in Audit logs.': return True
        if alert['signature'] == 'New login parameter combination in Audit logs.': return True
        if alert['signature'] == 'New user_start parameter combination in Audit logs.': return True

    return False


# TODO: this could be improved by checking if conditions for this stage are met (i.e. if privileges have been escalated)
def matches_escalated_sudo_command(alert: dict, ruleset: Ruleset):
    if ruleset == Ruleset.STRICT or ruleset == Ruleset.LENIENT or ruleset == Ruleset.LAX:
        # Wazuh rules
        if alert['signature'] == 'Successful sudo to ROOT executed.': return True
        if alert['signature'] == 'First time user executed sudo.': return True

    if ruleset == Ruleset.LENIENT or ruleset == Ruleset.LAX:
        # Wazuh rules
        if alert['signature'] == 'First time user executed sudo.': return True

        # AMiner rules
        if alert['signature'] == 'New user_cmd parameter combination in Audit logs.': return True
        if alert['signature'] == 'New cred_refr parameter combination in Audit logs.': return True

    if ruleset == Ruleset.LAX:
        # Wazuh rules
        if alert['signature'] == 'PAM: Login session opened.': return True
        if alert['signature'] == 'PAM: Login session closed.': return True

        # AMiner rules
        if alert['signature'] == 'New user_end parameter combination in Audit logs.': return True
        if alert['signature'] == 'New cred_disp parameter combination in Audit logs.': return True
        if alert['signature'] == 'New syscall parameter combination in Audit logs.': return True

    return False


def evaluate_rules(team_alerts: dict, ids: str, ruleset: Ruleset):
    # Combine alerts into a single list
    alerts = []
    for team in team_alerts.keys():
        alerts += team_alerts[team][ids]

    # Predict labels
    true_labels = []
    predicted_labels = []
    for alert in alerts:
        true_labels.append(alert['event_label'])
        predicted_labels.append(match_alert(alert, ruleset)[0])

    # Print results
    print_precision_recall(true_labels, predicted_labels)


HOST = 'intranet_server'
IDS = 'aminer'

if __name__ == '__main__':
    team_alerts = collect_alerts(HOST)

    # print_label_overview(team_alerts, 'wazuh')
    # print_label_overview(team_alerts, 'suricata')
    # print_label_overview(team_alerts, 'aminer')

    print(f'*** STRICT RULES ({IDS})***')
    evaluate_rules(team_alerts, IDS, Ruleset.STRICT)

    print(f'\n*** LENIENT RULES ({IDS})***')
    evaluate_rules(team_alerts, IDS, Ruleset.LENIENT)

    print(f'\n*** LAX RULES ({IDS})***')
    evaluate_rules(team_alerts, IDS, Ruleset.LAX)
