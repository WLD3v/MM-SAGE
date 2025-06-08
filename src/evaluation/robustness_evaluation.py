def evaluate_graphs(graph_path: str):
    modality_metrics = {
        'Correctness': [],
        'Conciseness': [],
        'Completeness': []
    }

    # Clean up the edges and calculate the values of the defined metrics
    for team in TEAMS:
        nodes, edges = collect_nodes_and_edges(graph_path, team)

        if len(edges) == 0:
            modality_metrics['Correctness'].append('0.000')
            modality_metrics['Conciseness'].append('0.000')
            modality_metrics['Completeness'].append('0.000')
        else:
            edges = process_edges(nodes, edges)

            correctness = round(calculate_correctness(edges, ATTACK_DESCRIPTIONS[team]), 3)
            conciseness = round(calculate_conciseness(edges, ATTACK_DESCRIPTIONS[team].copy()), 3)
            completeness = round(calculate_completeness(edges, ATTACK_DESCRIPTIONS[team]), 3)

            modality_metrics['Correctness'].append(convert_metric_to_str(correctness))
            modality_metrics['Conciseness'].append(convert_metric_to_str(conciseness))
            modality_metrics['Completeness'].append(convert_metric_to_str(completeness))

    return modality_metrics


def calculate_correctness(graph_edges: list, attack_description: list):
    nr_of_correct_edges = 0
    nr_of_graph_edges = len(graph_edges)

    # Determine how many of the edges in the graph are also in the attack description, with transitions that should have been merged being fine
    for edge in graph_edges:
        split = edge.split('-->')
        edge_state_1 = split[0]
        edge_state_2 = split[1]

        if edge in attack_description or edge_state_1 == edge_state_2:  # Allow edges that refer to a state that should have been merged
            nr_of_correct_edges += 1

    return nr_of_correct_edges / nr_of_graph_edges


def calculate_conciseness(graph_edges: list, attack_description: list):
    nr_of_correct_edges = 0
    nr_of_graph_edges = len(graph_edges)

    # Determine how many of the edges in the graph are also in the attack description, with transitions that should have been merged being penalized
    for edge in graph_edges:
        if edge in attack_description:
            attack_description.remove(edge)  # Remove (one instance of) the edge from the description to penalize edges that occur more than in the description
            nr_of_correct_edges += 1

    return nr_of_correct_edges / nr_of_graph_edges


def calculate_completeness(graph_edges: list, attack_description: list):
    nr_of_correct_edges = 0
    nr_of_description_edges = len(attack_description)

    for edge in attack_description:
        if edge in graph_edges:
            nr_of_correct_edges += 1

    return nr_of_correct_edges / nr_of_description_edges


def convert_metric_to_str(metric: int):
    str_metric = str(metric)

    # Format each result to have the same amount of numbers behind the decimal
    if len(str_metric) == 1:
        str_metric += '.00'

    elif len(str_metric) == 3:
        str_metric += '00'

    elif len(str_metric) == 4:
        str_metric += '0'

    return str_metric


def collect_nodes_and_edges(graph_path: str, team: str):
    nodes_file_path = f'{graph_path}/nodes_and_edges/{team}_nodes.txt'
    edges_file_path = f'{graph_path}/nodes_and_edges/{team}_edges.txt'

    nodes = []
    with open(nodes_file_path) as file:
        for line in file.readlines():
            nodes.append(line.replace('\n', ''))

    edges = []
    with open(edges_file_path) as file:
        for line in file.readlines():
            edges.append(line.replace('\n', ''))

    return nodes, edges


def process_edges(nodes: list, edges: list):
    duplicate_edges = []
    processed_edges = []
    for edge in edges:
        split = edge.split('-->')
        edge_state_1 = split[0]
        edge_state_2 = split[1]

        # Remove duplicate edges
        if edge in duplicate_edges:
            continue

        # Remove self referencing edges
        if edge_state_1 == edge_state_2:
            continue

        # Remove edges with sink states (if configured)
        if not USE_SINKS and contains_sink_state(edge, nodes):
            continue

        duplicate_edges.append(edge)

        # Remove state identifiers
        edge_state_1 = edge_state_1.split('-')[:-1][0]
        edge_state_2 = edge_state_2.split('-')[:-1][0]
        edge = edge_state_1 + '-->' + edge_state_2

        processed_edges.append(edge)

    return processed_edges


def contains_sink_state(edge: str, nodes: list):
    for node in nodes:
        split = node.split(',')
        state = split[0]
        model = split[1]

        split = edge.split('-->')
        edge_state_1 = split[0]
        edge_state_2 = split[1]

        # Check if any of the states in the given edge is a sink state
        if 'Sink' in model and (state == edge_state_1 or state == edge_state_2):
            return True

    return False


TEAMS = ['fox', 'harrison', 'russellmitchell', 'santos', 'shaw', 'wardbeck', 'wheeler', 'wilson']

ATTACK_DESCRIPTIONS = {
    'fox': [
        'service_scan-->wpscan',
        'wpscan-->dirb',
        'dirb-->webshell_cmd',
        'webshell_cmd-->online_cracking',
        'online_cracking-->attacker_change_user',
        'attacker_change_user-->escalated_sudo_command'
    ],
    'harrison': [
        'service_scan-->wpscan',
        'wpscan-->dirb',
        'dirb-->webshell_cmd',
        'webshell_cmd-->online_cracking',
        'online_cracking-->attacker_change_user',
        'attacker_change_user-->escalated_sudo_command'
    ],
    'russellmitchell': [
        'service_scan-->dirb',
        'dirb-->wpscan',
        'wpscan-->webshell_cmd',
        'webshell_cmd-->offline_cracking',
        'offline_cracking-->attacker_change_user',
        'attacker_change_user-->escalated_sudo_command'
    ],
    'santos': [
        'service_scan-->dirb',
        'dirb-->wpscan',
        'wpscan-->webshell_cmd',
        'webshell_cmd-->online_cracking',
        'online_cracking-->attacker_change_user',
        'attacker_change_user-->escalated_sudo_command'
    ],
    'shaw': [
        'service_scan-->wpscan',
        'wpscan-->dirb',
        'dirb-->webshell_cmd',
        'webshell_cmd-->online_cracking',
        'online_cracking-->attacker_change_user',
        'attacker_change_user-->escalated_sudo_command'
    ],
    'wardbeck': [
        'service_scan-->wpscan',
        'wpscan-->dirb',
        'dirb-->webshell_cmd',
        'webshell_cmd-->online_cracking',
        'online_cracking-->attacker_change_user',
        'attacker_change_user-->escalated_sudo_command'
    ],
    'wheeler': [
        'service_scan-->dirb',
        'dirb-->wpscan',
        'wpscan-->webshell_cmd',
        'webshell_cmd-->offline_cracking',
        'offline_cracking-->attacker_change_user',
        'attacker_change_user-->escalated_sudo_command'
    ],
    'wilson': [
        'service_scan-->dirb',
        'dirb-->wpscan',
        'wpscan-->webshell_cmd',
        'webshell_cmd-->online_cracking',
        'online_cracking-->attacker_change_user',
        'attacker_change_user-->escalated_sudo_command'
    ],
}

USE_SINKS = True

if __name__ == '__main__':
    print('*** EVALUATING GRAPHS ***')
    print(f'Sink states will {'NOT ' if USE_SINKS else ''}be removed')

    total_metrics = []
    for nr_of_detectors in range(1, 31):
        metrics = {
            'Alerts': evaluate_graphs(f'../../output/evaluation/robustness/alerts/{nr_of_detectors}'),
            'Logs': evaluate_graphs(f'../../output/evaluation/robustness/logs/{nr_of_detectors}'),
            'Alerts and Logs': evaluate_graphs(f'../../output/evaluation/robustness/alerts-and-logs/{nr_of_detectors}')
        }

        total_metrics.append(metrics)



    # Initialize lists that will contain the metrics for each detector set
    team_correctness = {}
    team_conciseness = {}
    team_completeness = {}

    team_correctness['Alerts'] = {}
    team_correctness['Logs'] = {}
    team_correctness['Alerts and Logs'] = {}
    team_conciseness['Alerts'] = {}
    team_conciseness['Logs'] = {}
    team_conciseness['Alerts and Logs'] = {}
    team_completeness['Alerts'] = {}
    team_completeness['Logs'] = {}
    team_completeness['Alerts and Logs'] = {}

    for team in TEAMS:
        team_correctness['Alerts'][team] = []
        team_correctness['Logs'][team] = []
        team_correctness['Alerts and Logs'][team] = []
        team_conciseness['Alerts'][team] = []
        team_conciseness['Logs'][team] = []
        team_conciseness['Alerts and Logs'][team] = []
        team_completeness['Alerts'][team] = []
        team_completeness['Logs'][team] = []
        team_completeness['Alerts and Logs'][team] = []

    for metrics in total_metrics:
        for mode in metrics.keys():
            for metric in metrics[mode].keys():
                for team_nr, value in enumerate(metrics[mode][metric]):
                    if metric == 'Correctness':
                        team_correctness[mode][TEAMS[team_nr]].append(value)
                    elif metric == 'Conciseness':
                        team_conciseness[mode][TEAMS[team_nr]].append(value)
                    elif metric == 'Completeness':
                        team_completeness[mode][TEAMS[team_nr]].append(value)


    for mode in team_correctness.keys():
        print(f'\n*** PRINTING {mode.upper()} CORRECTNESS RESULTS')
        for team in team_correctness[mode].keys():
            print(f'{team} = {team_correctness[mode][team]}')

        print(f'\n*** PRINTING {mode.upper()} CONCISENESS RESULTS')
        for team in team_conciseness[mode].keys():
            print(f'{team} = {team_conciseness[mode][team]}')

        print(f'\n*** PRINTING {mode.upper()} COMPLETENESS RESULTS')
        for team in team_completeness[mode].keys():
            print(f'{team} = {team_completeness[mode][team]}')