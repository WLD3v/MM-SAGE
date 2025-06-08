from helpers.file_helper import read_json
from helpers.map_helper import log_labels_to_observable_label

if __name__ == '__main__':
    teams = ['fox', 'harrison', 'russellmitchell', 'santos', 'shaw', 'wardbeck', 'wheeler', 'wilson']
    numbers = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']

    logs = []
    for team in teams:
        logs += read_json(f'../../output/team_logs/{team}_logs.json')

    log_dict = {}
    for log in logs:
        # Read variables from the json log
        host = log['host']
        file = log['file']
        labels = log['labels']
        label = log_labels_to_observable_label['|'.join(labels)]
        labels = [label]

        # Make part file names generic
        for number in numbers:
            if file[-2:] == '.' + number:
                file = file[:-2]

        # Make team specific file names generic
        if 'access.log' in file or 'error.log' in file:
            split = file.split('.')
            file = split[0] + '.' + split[-1]

        # Ensure the analysis dict has the needed keys
        if host not in log_dict.keys():
            log_dict[host] = {}

        if file not in log_dict[host].keys():
            log_dict[host][file] = {}

        for label in labels:
            if label not in log_dict[host][file].keys():
                log_dict[host][file][label] = []

        # Add data to the dict for analysis
        for label in labels:
            log_dict[host][file][label].append(log)


    log_counter = 0
    for host in log_dict.keys():
        for file in log_dict[host].keys():
            for label in log_dict[host][file].keys():
                count = len(log_dict[host][file][label])
                log_counter += count
                print(f'{host.replace('_', '\\_')} & {file} & {label.replace('_', '\\_')} & {count} \\\\')

    assert len(logs) >= log_counter, 'Discarded labels during log analysis'
    assert len(logs) <= log_counter, 'Duplicated labels during log analysis'

    print(f'Read a total of {len(logs)} log lines')
