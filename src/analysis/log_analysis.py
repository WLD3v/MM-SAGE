import os
import json

from helpers.analysis_helper import print_precision_recall
from helpers.file_helper import read_json
from helpers.map_helper import log_labels_to_observable_label
from enum import Enum


class Ruleset(Enum):
    STRICT = 'STRICT'
    LENIENT = 'LENIENT'
    LAX = 'LAX'


def collect_logs(hosts: list):
    team_logs = {}

    for file in os.listdir('../../output/logs'):
        team = file.split('_')[0]

        logs = read_json(f'../../output/logs/{file}')
        logs = [log for log in logs if log['host'] in hosts]

        team_logs[team] = logs

    return team_logs


def match_line(line: str, ruleset: Ruleset):
    labels = []

    if matches_service_scan(line, ruleset): labels.append('service_scan')
    if matches_dirb(line, ruleset): labels.append('dirb')
    if matches_wpscan(line, ruleset): labels.append('wpscan')
    if matches_webshell_cmd(line, ruleset): labels.append('webshell_cmd')
    if matches_online_cracking(line, ruleset): labels.append('online_cracking')
    if matches_attacker_change_user(line, ruleset): labels.append('attacker_change_user')
    if matches_escalated_sudo_command(line, ruleset): labels.append('escalated_sudo_command')

    assert len(labels) <= 1, f'Found multiple matching labels {labels} for log line: {line}'

    if len(labels) == 0: return ['-']

    return labels


# Service scans are detected in the access logs (e.g. intranet.price.fox.org-access.log.2)
# (e.g. 172.17.130.196 - - [18/Jan/2022:12:17:43 +0000] "GET /nmaplowercheck1642508263 HTTP/1.1" 404 360 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)")
def matches_service_scan(line: str, ruleset: Ruleset):
    if ruleset == Ruleset.STRICT or ruleset == Ruleset.LENIENT or ruleset == Ruleset.LAX:
        if 'https://nmap.org/book/nse.html' in line:
            return True

    if ruleset == Ruleset.LAX:
        if '"GET / HTTP' in line and '"-" "-"' in line:
            return True

    return False


# TODO: this rule can potentially be improved by considering the log entry volume per unit of time
# TODO: check where rules with overlap should be applied
# DIRB site scans are detected in the error logs and access logs (such as intranet.hallbrown.wilson.com-error.log.2 and intranet.price.fox.org-access.log.2)
# (e.g. [Mon Feb 07 11:19:31.234176 2022] [authz_core:error] [pid 5867] [client 10.182.193.78:58790] AH01630: client denied by server configuration: /var/www/intranet.hallbrown.wilson.com/wp-includes/js/tinymce/skins/wordpress/images/.htpasswd_)
def matches_dirb(line: str, ruleset: Ruleset):
    if ruleset == Ruleset.LENIENT or ruleset == Ruleset.LAX:
        if '[authz_core:error]' in line and 'client denied by server configuration' in line:
            return True

        # Also occurs during the WPScan stage
        if '[autoindex:error]' in line and 'Cannot serve directory' in line and 'No matching DirectoryIndex' in line:
            return True

        # Also occurs during the WPScan stage
        if '[negotiation:error]' in line and 'Negotiation: discovered file(s) matching request:' in line and 'None could be negotiated' in line:
            return True

    if ruleset == Ruleset.LAX:
        # Also occurs during the WPScan stage
        if '[php7:error]' in line and 'not found or unable to stat' in line:
            return True

        if '[php7:warn]' in line and 'Use of undefined constant' in line:
            return True

    return False


# WP scans are detected in the access logs (e.g. intranet.hallbrown.wilson.com-access.log.2)
# (e.g. [07/Feb/2022:11:20:19 +0000] "POST /wp-login.php HTTP/1.1" 200 2675 "https://intranet.hallbrown.wilson.com" "WPScan v3.8.20 (https://wpscan.com/wordpress-security-scanner)"
def matches_wpscan(line: str, ruleset: Ruleset):
    if ruleset == Ruleset.STRICT or ruleset == Ruleset.LENIENT or ruleset == Ruleset.LAX:
        if 'https://wpscan.com/wordpress-security-scanner' in line:
            return True

    return False


# The reverse shell upload is detected in the access logs (e.g. intranet.price.fox.org-access.log.2)
# (e.g. 172.17.130.196 - - [18/Jan/2022:12:38:16 +0000] "GET /wp-content/uploads/2022/01/yqagisjaqe-1642509481.8663.php?wp_meta=WyJjYXQiLCAiL2V0Yy9ncm91cCJd HTTP/1.1" 200 507443 "-" "python-requests/2.27.1")
def matches_webshell_cmd(line: str, ruleset: Ruleset):
    if ruleset == Ruleset.STRICT or ruleset == Ruleset.LENIENT or ruleset == Ruleset.LAX:
        if '/wp-content/uploads/' in line and '.php' in line and 'python-requests' in line:
            return True

    if ruleset == Ruleset.LENIENT or ruleset == Ruleset.LAX:
        if 'POST' in line and 'python-requests' in line:
            return True

    if ruleset == Ruleset.LAX:
        if 'GET' in line and 'python-requests' in line:
            return True

    return False

# TODO: reduce the number of false positives
# The password cracking is detected in the monitoring CPU logs (e.g. 2022-01-17-system.cpu.log)
# (e.g. {"@timestamp":"2022-01-18T12:39:39.321Z","service":{"type":"system"},"tags":["beats_input_raw_event"],"@version":"1","agent":{"type":"metricbeat","hostname":"intranet-server","version":"7.13.2","id":"a0c41e4e-ff4a-481f-adda-21fc96889b28","name":"intranet-server","ephemeral_id":"ae20c47b-0a81-4e05-a749-cbe0dacd5e36"},"system":{"cpu":{"softirq":{"pct":0.0068,"norm":{"pct":0.0068}},"iowait":{"pct":0.0077,"norm":{"pct":0.0077}},"nice":{"pct":0.5908,"norm":{"pct":0.5908}},"cores":1,"idle":{"pct":0.2235,"norm":{"pct":0.2235}},"system":{"pct":0.0947,"norm":{"pct":0.0947}},"total":{"pct":0.7688,"norm":{"pct":0.7688}},"steal":{"pct":0.0023,"norm":{"pct":0.0023}},"user":{"pct":0.0743,"norm":{"pct":0.0743}},"irq":{"pct":0,"norm":{"pct":0}}}},"event":{"duration":421770,"dataset":"system.cpu","module":"system"},"metricset":{"name":"cpu","period":45000},"ecs":{"version":"1.9.0"},"host":{"cpu":{"pct":0.7688},"name":"intranet-server"}})
def matches_online_cracking(line: str, ruleset: Ruleset):
    # We can only match results from the monitoring hosts
    if '"dataset":"system.cpu"' not in line:
        return False

    line = json.loads(line)

    cpu_usage = line['host']['cpu']['pct']
    cpu_period = line['metricset']['period']

    if ruleset == Ruleset.STRICT or ruleset == Ruleset.LENIENT or ruleset == Ruleset.LAX:
        if cpu_usage >= 0.9 and cpu_period >= 45000:
            return True

    if ruleset == Ruleset.STRICT or ruleset == Ruleset.LENIENT:
        if cpu_usage >= 0.75 and cpu_period >= 45000:
            return True

    if ruleset == Ruleset.LAX:
        if cpu_usage >= 0.5 and cpu_period >= 45000:
            return True

    return False


# The privilege escalation is detected in the audit and auth logs (e.g. audit.log)
# (e.g. Feb  7 11:48:18 intranet-server su[6084]: Successful su for jwilkinson by www-data)
def matches_attacker_change_user(line: str, ruleset: Ruleset):
    if ruleset == Ruleset.STRICT or ruleset == Ruleset.LENIENT or ruleset == Ruleset.LAX:
        if 'Successful su' in line and 'www-data' in line:
            return True

    if ruleset == Ruleset.LENIENT or ruleset == Ruleset.LAX:
        if 'type=USER_AUTH' in line and 'exe="/bin/su"' in line:

            # These attacker accounts are identified by manually analysing the logs
            for attacker in ATTACKER_ACCOUNTS:
                if attacker in line:
                    return True

    # TODO: consider replacing this rule with "any mention of an attacker account"
    if ruleset == Ruleset.LAX:
        if 'exe="/bin/su"' in line:
            return True

    return False


# The escalated sudo commands are found in the audit and auth logs (e.g. audit.log)
# (e.g. type=USER_CMD msg=audit(1644309417.304:2919): pid=28346 uid=1001 auid=4294967295 ses=4294967295 msg='cwd="/var/www/intranet.mannsmith.harrison.com/wp-content/uploads/2022/02" cmd=636174202F6574632F736861646F77 terminal=pts/0 res=success')
def matches_escalated_sudo_command(line: str, ruleset: Ruleset):
    if ruleset == Ruleset.LAX:
        if 'USER=root' in line and 'COMMAND=' in line:
            return True

        if 'uid=0' in line and 'type=USER_CMD':
            return True

    return False


def evaluate_rules(team_logs: dict, ruleset: Ruleset):
    # Combine logs into a single list
    logs = []
    for team in team_logs.keys():
        logs += team_logs[team]

    # Predict labels
    true_labels = []
    predicted_labels = []
    for log in logs:
        true_labels.append(log_labels_to_observable_label['|'.join(log['labels'])])
        predicted_labels.append(match_line(log['raw'], ruleset)[0])

    # Print results
    print_precision_recall(true_labels, predicted_labels)


HOSTS = ['intranet_server', 'monitoring']
ATTACKER_ACCOUNTS = ['phopkins', 'jward', 'jhall', 'gmorgan', 'gmarsh', 'blord', 'kford', 'jwilkinson']

if __name__ == '__main__':
    team_logs = collect_logs(HOSTS)

    print('*** STRICT RULES ***')
    evaluate_rules(team_logs, Ruleset.STRICT)

    print('\n*** LENIENT RULES ***')
    evaluate_rules(team_logs, Ruleset.LENIENT)

    print('\n*** LAX RULES ***')
    evaluate_rules(team_logs, Ruleset.LAX)

    # This code was used to manually inspect log lines for rule creation
    # for team, logs in team_logs.items():
    #     for log in logs:
    #         line = log['raw']
    #         file = log['file']

            # Check which rules are matched and collect the true label
            # matched_labels = match_line(line, Ruleset.LAX)
            # matched_label = matched_labels[0]
            # true_label = log_labels_to_observable_label['|'.join(log['labels'])]

            # Remaining false-negatives are empty access log entries
            # (e.g. 172.17.130.196 - - [18/Jan/2022:12:17:37 +0000] "GET / HTTP/1.0" 200 17571 "-" "-")
            # if true_label == 'service_scan' and matched_label != 'service_scan':
            #     print(f'[{team}] --> {file} --> {line}')

            # # Remaining false-negatives are general "resource not found" lines or general GET requests
            # # (e.g. [07/Feb/2022:11:19:42 +0000] "GET /wp-includes/js/tinymce/skins/wordpress/images/rules HTTP/1.1" 404 363 "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)")
            # if true_label == 'dirb' and matched_label != 'dirb':
            #     print(f'[{team}] --> {file} --> {line}')

            # # Remaining false-negatives are general "resource not found" lines
            # # (e.g. [Tue Jan 18 12:17:52.008720 2022] [php7:error] [pid 28411] [client 172.17.130.196:55206] script '/var/www/intranet.price.fox.org/searchreplacedb2.php' not found or unable to stat, referer: https://intranet.price.fox.org)
            # if true_label == 'wpscan' and matched_label != 'wpscan':
            #     print(f'[{team}] --> {file} --> {line}')

            # # Remaining false-negatives are GET requests relating to php scripts
            # # (e.g. [18/Jan/2022:12:38:00 +0000] "GET / HTTP/1.1" 200 9186 "-" "python-requests/2.27.1")
            # if true_label == 'webshell_cmd' and matched_label != 'webshell_cmd':
            #     print(f'[{team}] --> {file} --> {line}')

            # # Online cracking is only detected by monitoring, which we currently see as a different host
            # # (e.g. \"@timestamp\":\"2022-01-18T12:45:39.321Z\",\"service\":{\"type\":\"system\"},\"tags\":[\"beats_input_raw_event\"],\"@version\":\"1\",\"agent\":{\"type\":\"metricbeat\",\"hostname\":\"intranet-server\",\"version\":\"7.13.2\",\"id\":\"a0c41e4e-ff4a-481f-adda-21fc96889b28\",\"name\":\"intranet-server\",\"ephemeral_id\":\"ae20c47b-0a81-4e05-a749-cbe0dacd5e36\"},\"system\":{\"cpu\":{\"softirq\":{\"pct\":0.0027,\"norm\":{\"pct\":0.0027}},\"cores\":1,\"iowait\":{\"pct\":0,\"norm\":{\"pct\":0}},\"nice\":{\"pct\":0.9275,\"norm\":{\"pct\":0.9275}},\"idle\":{\"pct\":0,\"norm\":{\"pct\":0}},\"system\":{\"pct\":0.0407,\"norm\":{\"pct\":0.0407}},\"total\":{\"pct\":1,\"norm\":{\"pct\":1}},\"steal\":{\"pct\":0.0011,\"norm\":{\"pct\":0.0011}},\"user\":{\"pct\":0.028,\"norm\":{\"pct\":0.028}},\"irq\":{\"pct\":0,\"norm\":{\"pct\":0}}}},\"event\":{\"duration\":270236,\"module\":\"system\",\"dataset\":\"system.cpu\"},\"metricset\":{\"name\":\"cpu\",\"period\":45000},\"ecs\":{\"version\":\"1.9.0\"},\"host\":{\"name\":\"intranet-server\",\"cpu\":{\"pct\":1}}
            # if true_label == 'online_cracking' and matched_label != 'online_cracking':
            #     print(f'[{team}] --> {file} --> {line}')

            # # Remaining false-negatives are general session entries
            # # (e.g. type=USER_START msg=audit(1642942501.359:2984): pid=28708 uid=33 auid=4294967295 ses=4294967295 msg='op=PAM:session_open acct="blord" exe="/bin/su" hostname=? addr=? terminal=/dev/pts/1 res=success')
            # if true_label == 'attacker_change_user' and matched_label != 'attacker_change_user':
            #     print(f'[{team}] --> {file} --> {line}')

            # # Remaining false-negatives are general session entries
            # # (e.g. type=USER_END msg=audit(1644234531.066:3040): pid=6118 uid=0 auid=4294967295 ses=4294967295 msg='op=PAM:session_close acct="root" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/1 res=success')
            # if true_label == 'escalated_sudo_command' and matched_label != 'escalated_sudo_command':
            #     print(f'[{team}] --> {file} --> {line}')
