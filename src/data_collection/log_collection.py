from classes.log_label import LogLabel
from classes.log_line import LogLine
from helpers.file_helper import read_json_lines, write_json

from datetime import datetime, timezone

import json
import time
import os


def collect_team_labels(teams: list):
    print('(1) COLLECTING LABELS')

    team_labels = {}

    for team in teams:
        labels = {}

        # Collect host directories that contain labelled data
        label_directory = f'../../input/AIT-LDS/{team}/labels'
        hosts = os.listdir(label_directory)

        for host in hosts:
            labels[host] = {}

            # Recursively collect file paths for files on the given host
            files = collect_files(f'{label_directory}/{host}')

            # Parse and store labels as LogLabel objects
            for file in files:
                filename = file.split('/')[-1]

                labels[host][filename] = [LogLabel(label) for label in read_json_lines(file)]

        total_hosts = labels.keys()
        total_files = [filename for host in labels.keys() for filename in labels[host].keys()]
        total_labels = [label for host in labels.keys() for filename in labels[host].keys() for label in labels[host][filename]]

        print(f'[{team}] | Collected {len(total_labels)} labels from {len(total_files)} files spread over {len(total_hosts)} hosts')

        team_labels[team] = labels

    return team_labels


def collect_files(path: str):
    paths = []

    for root, _, filenames in os.walk(path):
        for filename in filenames:
            paths.append(os.path.join(root, filename).replace('\\', '/'))

    return paths


def collect_team_logs(team_labels: dict):
    print('\n(2) COLLECTING LOGS')

    team_logs = {}

    for team in team_labels.keys():
        logs = {}

        # Collect host directories that contain labelled data
        log_directory = f'../../input/AIT-LDS/{team}/gather'
        hosts = os.listdir(log_directory)

        for host in hosts:
            # Skip hosts that have no labelled files
            if host not in team_labels[team].keys():
                continue

            logs[host] = {}

            # Recursively collect file paths for files on the given host
            files = collect_files(f'{log_directory}/{host}')

            # Parse and store labels as LogLine objects
            for file in files:
                filename = file.split('/')[-1]

                # Skip files that have no labelled log lines
                if filename not in team_labels[team][host].keys():
                    continue

                # Follow parse instructions specific to the file
                logs[host][filename] = process_log(file, filename)

        total_hosts = logs.keys()
        total_files = [filename for host in logs.keys() for filename in logs[host].keys()]
        total_log_lines = [line for host in logs.keys() for filename in logs[host].keys() for line in logs[host][filename]]

        print(f'[{team}] | Collected {len(total_log_lines)} log lines from {len(total_files)} files spread over {len(total_hosts)} hosts')

        team_logs[team] = logs

    return team_logs


def process_log(path: str, filename: str):
    lines = []

    with open(path, 'r') as file:
        for line_index, line in enumerate(file.readlines()):

            # e.g. {"@timestamp":"2022-01-18T00:00:39.362Z","service":{"type":"system"},"tags":["beats_input_raw_event"],"@version":"1","agent":{"type":"metricbeat","hostname":"internal-share","version":"7.13.2","id":"c2af691d-8b2f-4193-bbfe-f5cde9a0563a","name":"internal-share","ephemeral_id":"9a9d03e6-2f24-4abc-a94f-563307e8c4b3"},"system":{"cpu":{"softirq":{"pct":0.0012,"norm":{"pct":0.0012}},"cores":1,"nice":{"pct":0,"norm":{"pct":0}},"iowait":{"pct":0.0017,"norm":{"pct":0.0017}},"idle":{"pct":0.9162,"norm":{"pct":0.9162}},"system":{"pct":0.0435,"norm":{"pct":0.0435}},"total":{"pct":0.0821,"norm":{"pct":0.0821}},"steal":{"pct":0.0054,"norm":{"pct":0.0054}},"user":{"pct":0.0321,"norm":{"pct":0.0321}},"irq":{"pct":0,"norm":{"pct":0}}}},"event":{"duration":588870,"dataset":"system.cpu","module":"system"},"metricset":{"name":"cpu","period":45000},"ecs":{"version":"1.9.0"},"host":{"cpu":{"pct":0.0821},"name":"internal-share"}}
            if 'cpu.log' in filename:
                line_json = json.loads(line)
                timestamp = line_json['@timestamp']
                timestamp = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)

                lines.append(LogLine(line_index + 1, timestamp, line))

            # e.g. 172.17.130.196 - - [18/Jan/2022:08:02:04 +0000] "GET / HTTP/1.1" 200 6128 "-" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/95.0.4638.69 Safari/537.36"
            elif '-access.log' in filename:
                split = line.split(' ')
                timestamp = split[3].replace('[', '')
                timestamp = datetime.strptime(timestamp, "%d/%b/%Y:%H:%M:%S").replace(tzinfo=timezone.utc)

                lines.append(LogLine(line_index + 1, timestamp, line))

            # e.g. [Tue Jan 18 10:07:23.284717 2022] [php7:warn] [pid 27406] [client 10.35.35.206:32894] PHP Warning:  scandir(/var/www/intranet.price.fox.org/wp-content/uploads/wpdiscuz/cache/gravatars/): failed to open dir: No such file or directory in /var/www/intranet.price.fox.org/wp-content/plugins/wpdiscuz/utils/class.WpdiscuzCache.php on line 190
            elif '-error.log' in filename:
                split = line.split(' ')
                timestamp = ' '.join(split[0:5]).replace('[', '').replace(']', '')
                timestamp = datetime.strptime(timestamp, "%a %b %d %H:%M:%S.%f %Y").replace(tzinfo=timezone.utc)

                lines.append(LogLine(line_index + 1, timestamp, line))

            # e.g. type=USER_ACCT msg=audit(1642205821.573:157): pid=15311 uid=0 auid=4294967295 ses=4294967295 msg='op=PAM:accounting acct="root" exe="/usr/sbin/cron" hostname=? addr=? terminal=cron res=success'
            elif 'audit.log' in filename:
                split = line.split(' ')
                timestamp = float(split[1].replace('msg=audit(', '').replace('):', '').split(':')[0])
                timestamp = datetime.fromtimestamp(timestamp).replace(tzinfo=timezone.utc)

                lines.append(LogLine(line_index + 1, timestamp, line))

            # e.g. 2022-01-15 00:41:37 hwarren/192.168.129.254:41251 TLS: soft reset sec=3533/3533 bytes=58512/-1 pkts=753/0
            elif 'openvpn.log' in filename:
                split = line.split(' ')
                timestamp = ' '.join(split[0:2])
                timestamp = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")

                lines.append(LogLine(line_index + 1, timestamp, line))

            # e.g. Feb  8 04:17:01 intranet-server CRON[9159]: pam_unix(cron:session): session closed for user root
            elif 'auth.log' in filename:
                try:
                    split = line.split(' ')
                    timestamp = ' '.join(split[0:3])
                    timestamp = datetime.strptime(timestamp, "%b %d %H:%M:%S").replace(year=2022)

                    lines.append(LogLine(line_index + 1, timestamp, line))

                # Skip cases where the timestamp does not provide sufficient information (e.g. 'Feb  2022')
                except ValueError:
                    continue

            # e.g. Jan 15 00:00:03 dnsmasq[14522]: query[A] 3x6-.546-.2PoxC1PkS*qtk0p2kKZGSYsWe2X*u678tHnPA6vJb6cp7itF6Qlb7/ZNOUZ*-.tO4afCcp4TpC6S0KJF27aqpRaGLcHzZCkPnUWPug2PpcImBWfcLFKlm5p5r3-.Ewvg4xYu8FqM2a/lO4V8qfcNr2i1bRY/u8wZM19IvDh7deB7cBxUezv5CAKT-.customers_2018.xlsx.ycgjslfptkev.com from 10.35.33.111
            elif 'dnsmasq.log' in filename:
                try:
                    split = line.split(' ')
                    timestamp = ' '.join(split[0:3]) + ' 2022'
                    timestamp = datetime.strptime(timestamp, "%b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)

                    lines.append(LogLine(line_index + 1, timestamp, line))

                # Skip cases where the timestamp does not provide sufficient information (e.g. 'Feb  2022')
                except ValueError:
                    continue

            else:
                raise ValueError(f'File "{filename}" has no matching parser')

    return lines


def update_logs(team_labels: dict, team_logs: dict):
    print('\n(3) UPDATING LOGS')

    for team in team_labels.keys():
        for host in team_labels[team].keys():
            for filename in team_labels[team][host].keys():

                lines = []
                for label in team_labels[team][host][filename]:
                    # Prevent out-of-bound issues caused by skipped lines in auth.log and dnsmasq.log
                    if len(team_logs[team][host][filename]) <= label.line_nr - 1:
                        continue

                    line = team_logs[team][host][filename][label.line_nr - 1]
                    line.labels = label.labels
                    line.host = host
                    line.file = filename

                    assert line.line_nr == label.line_nr

                    lines.append(line)

                team_logs[team][host][filename] = lines

        total_hosts = team_logs[team].keys()
        total_files = [filename for host in team_logs[team].keys() for filename in team_logs[team][host].keys()]
        total_log_lines = [line for host in team_logs[team].keys() for filename in team_logs[team][host].keys() for line in team_logs[team][host][filename]]

        print(f'[{team}] | Labelled {len(total_log_lines)} log lines from {len(total_files)} files spread over {len(total_hosts)} hosts')

    return team_logs


def save_logs(team_logs: dict):
    directory = '../../output/team_logs'

    for team in team_logs.keys():

        data = []
        for host in team_logs[team].keys():
            for file in team_logs[team][host].keys():
                lines = team_logs[team][host][file]

                for line in lines:
                    data.append(line.to_dict())

        path = f'{directory}/{team}_logs.json'
        write_json(path, data)

    print(f'\nSaved results under {directory}')


if __name__ == '__main__':
    print('*** COLLECTING LOG ENTRIES ***')
    start_time = time.time()

    teams = ['fox', 'harrison', 'russellmitchell', 'santos', 'shaw', 'wardbeck', 'wheeler', 'wilson']

    team_labels = collect_team_labels(teams)
    team_logs = collect_team_logs(team_labels)
    team_logs = update_logs(team_labels, team_logs)

    save_logs(team_logs)

    print(f'\nSTAGE COMPLETED AFTER {round(time.time() - start_time)} SECONDS')
