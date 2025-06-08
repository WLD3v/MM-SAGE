import os
import matplotlib.pyplot as plt

from helpers.constant_helper import ATTACK_DESCRIPTIONS


def collect_nodes_and_edges():
    nodes_and_edges = {}

    for ruleset in RULESETS:
        nodes_and_edges[ruleset] = {}

        for modalities in MODALITY_COMBINATIONS:
            nodes_and_edges[ruleset][modalities] = {}

            for file in os.listdir(f'../../output/evaluation/quality/{ruleset}/{modalities}/nodes_and_edges/'):
                team = file.split('_')[0]
                nodes_or_edges = file.split('_')[1].split('.')[0]

                if team not in nodes_and_edges[ruleset][modalities].keys():
                    nodes_and_edges[ruleset][modalities][team] = {}

                nodes_and_edges[ruleset][modalities][team][nodes_or_edges] = read_nodes_or_edges(f'../../output/evaluation/quality/{ruleset}/{modalities}/nodes_and_edges/{file}')

    return nodes_and_edges


def read_nodes_or_edges(path: str):
    data = []
    with open(path) as file:
        for line in file.readlines():
            data.append(line.replace('\n', ''))

    return data


def process_nodes_and_edges(nodes_and_edges: dict):
    for ruleset in RULESETS:
        for modalities in MODALITY_COMBINATIONS:
            for team in nodes_and_edges[ruleset][modalities].keys():
                nodes = nodes_and_edges[ruleset][modalities][team]['nodes']
                edges = nodes_and_edges[ruleset][modalities][team]['edges']

                duplicate_edges = []
                processed_edges = []
                for edge in edges:
                    split = edge.split('-->')
                    edge_state_1 = split[0]
                    edge_state_2 = split[1]

                    # Remove self referencing edges
                    if edge_state_1 == edge_state_2:
                        continue

                    # Remove duplicate edges
                    if edge in duplicate_edges:
                        continue

                    duplicate_edges.append(edge)

                    # Remove state identifiers
                    edge_state_1 = edge_state_1.split('-')[:-1][0]
                    edge_state_2 = edge_state_2.split('-')[:-1][0]
                    edge = edge_state_1 + '-->' + edge_state_2

                    processed_edges.append(edge)

                nodes_and_edges[ruleset][modalities][team]['edges'] = processed_edges

    return nodes_and_edges


# Correctness checks how much of the information in the graph is correct, disregarding redundant information
def calculate_correctness(graph_edges: list, attack_description: list):
    nr_of_correct_edges = 0
    nr_of_graph_edges = len(graph_edges)

    # Prevent division by zero
    if nr_of_graph_edges == 0:
        return 0

    # Determine how many of the edges in the graph are also in the attack description, with transitions that should have been merged being fine
    for edge in graph_edges:
        split = edge.split('-->')
        edge_state_1 = split[0]
        edge_state_2 = split[1]

        # Allow edges that refer to a state that should have been merged
        if edge in attack_description or edge_state_1 == edge_state_2:
            nr_of_correct_edges += 1

    return nr_of_correct_edges / nr_of_graph_edges


# Conciseness compares the ideal size of the graph to the actual size of the graph, disregarding the information the graph contains
def calculate_conciseness(graph_edges: list, attack_description: list):
    nr_of_description_edges = len(attack_description)
    nr_of_graph_edges = len(graph_edges)

    # Prevent division by zero
    if nr_of_graph_edges == 0:
        return 1

    return min(nr_of_description_edges / nr_of_graph_edges, 1)


# Completeness checks how much of the attack is represented in the attack graph, disregarding how much incorrect or redundant information the graph contains
def calculate_completeness(graph_edges: list, attack_description: list):
    nr_of_description_edges_in_graph = 0
    nr_of_description_edges = len(attack_description)

    for edge in attack_description:
        if edge in graph_edges:
            nr_of_description_edges_in_graph += 1

    return nr_of_description_edges_in_graph / nr_of_description_edges


def calculate_metrics(nodes_and_edges: dict):
    metrics = {}

    for ruleset in RULESETS:
        metrics[ruleset] = {}

        for modalities in MODALITY_COMBINATIONS:
            metrics[ruleset][modalities] = {}

            for team in nodes_and_edges[ruleset][modalities].keys():
                edges = nodes_and_edges[ruleset][modalities][team]['edges']

                correctness = calculate_correctness(edges, ATTACK_DESCRIPTIONS[team])
                conciseness = calculate_conciseness(edges, ATTACK_DESCRIPTIONS[team].copy())
                completeness = calculate_completeness(edges, ATTACK_DESCRIPTIONS[team])

                metrics[ruleset][modalities][team] = {}
                metrics[ruleset][modalities][team]['correctness'] = correctness
                metrics[ruleset][modalities][team]['conciseness'] = conciseness
                metrics[ruleset][modalities][team]['completeness'] = completeness

    return metrics


def save_metrics(metrics: dict):
    for ruleset in RULESETS:
        graph_correctness = {}
        graph_conciseness = {}
        graph_completeness = {}

        table_correctness = {}
        table_conciseness = {}
        table_completeness = {}

        for modalities in MODALITY_COMBINATIONS:
            correctness = []
            conciseness = []
            completeness = []

            for team in metrics[ruleset][modalities].keys():
                correctness.append(metrics[ruleset][modalities][team]['correctness'])
                conciseness.append(metrics[ruleset][modalities][team]['conciseness'])
                completeness.append(metrics[ruleset][modalities][team]['completeness'])

                if team not in table_correctness.keys():
                    table_correctness[team] = []
                    table_conciseness[team] = []
                    table_completeness[team] = []

                table_correctness[team].append(metrics[ruleset][modalities][team]['correctness'])
                table_conciseness[team].append(metrics[ruleset][modalities][team]['conciseness'])
                table_completeness[team].append(metrics[ruleset][modalities][team]['completeness'])

            # Save the average metrics for graph plotting
            graph_correctness[modalities] = sum(correctness) / len(correctness)
            graph_conciseness[modalities] = sum(conciseness) / len(conciseness)
            graph_completeness[modalities] = sum(completeness) / len(completeness)

        plot_metric(graph_correctness, 'correctness', ruleset)
        plot_metric(graph_conciseness, 'conciseness', ruleset)
        plot_metric(graph_completeness, 'completeness', ruleset)

        # print_table(table_correctness, 'correctness')
        # print_table(table_conciseness, 'conciseness')
        # print_table(table_completeness, 'completeness')


def plot_metric(metric: dict, metric_name: str, ruleset: str):
    modalities = MODALITY_COMBINATIONS_SHORT
    metrics = list(metric.values())

    plt.figure(figsize=(8, 4))
    bars = plt.bar(modalities, metrics, color=BAR_COLORS[ruleset])
    plt.xticks(rotation=45)
    plt.ylabel(metric_name)
    plt.grid(axis='y')
    plt.ylim(0, 1)

    # Add values above the bars
    for bar in bars:
        plt.text(bar.get_x() + bar.get_width() / 2., bar.get_height(), f'{bar.get_height():.3f}', ha='center')

    # Create the chart directory if it does not exist
    if not os.path.exists(f'../../output/evaluation/quality/{ruleset}/charts'):
        os.makedirs(f'../../output/evaluation/quality/{ruleset}/charts')

    plt.tight_layout()
    plt.savefig(f'../../output/evaluation/quality/{ruleset}/charts/{metric_name}-chart.png')
    plt.close()


def print_table(metric: dict, metric_name: str):
    print('\n\\begin{table}[h]')
    print('\\centering')
    print('\\begin{tabular}{|c|c|c|c|c|c|c|c|c|}')
    print('\\hline')

    for team in metric.keys():
        print(f' & {team}', end='')
    print('\\\\ \\hline')

    for index, modality in enumerate(MODALITY_COMBINATIONS_SHORT):
        print(f'{modality} ', end='')

        for results in metric.values():
            print(f' & {convert_metric_to_str(results[index])}', end='')
        print('\\\\ \\hline')

    print('\\end{tabular}')
    print('\\caption{' + metric_name.capitalize() + ' of generated attack graphs per-scenario and per-modality-combination.}')
    print('\\label{tab:' + metric_name + '-table}')
    print('\\end{table}')


def convert_metric_to_str(metric: int):
    metric = round(metric, 3)
    str_metric = str(metric)

    # Format each result to have the same amount of numbers behind the decimal
    if len(str_metric) == 1:
        str_metric += '.00'

    elif len(str_metric) == 3:
        str_metric += '00'

    elif len(str_metric) == 4:
        str_metric += '0'

    return str_metric


# These parameters have been used during testing
RULESETS = [
    'labels',
    'Ruleset.LAX',
    'Ruleset.LENIENT',
    'Ruleset.STRICT'
]

# These parameters have been used during testing
MODALITY_COMBINATIONS = [
    'suricata',
    'aminer',
    'wazuh',
    'suricata-aminer',
    'wazuh-aminer',
    'wazuh-suricata',
    'wazuh-suricata-aminer',
    'logs',
    'logs-suricata',
    'logs-aminer',
    'logs-wazuh',
    'logs-suricata-aminer',
    'logs-wazuh-aminer',
    'logs-wazuh-suricata',
    'logs-wazuh-suricata-aminer'
]

MODALITY_COMBINATIONS_SHORT = [
    'sur',
    'am',
    'waz',
    'sur-am',
    'waz-am',
    'waz-sur',
    'waz-sur-am',
    'log',
    'log-sur',
    'log-am',
    'log-waz',
    'log-sur-am',
    'log-waz-am',
    'log-waz-sur',
    'log-waz-sur-am'
]

BAR_COLORS = {
    'labels': 'green',
    'Ruleset.STRICT': 'blue',
    'Ruleset.LENIENT': 'orange',
    'Ruleset.LAX': 'red'
}

if __name__ == '__main__':
    for ruleset in RULESETS:
        nodes_and_edges = collect_nodes_and_edges()
        nodes_and_edges = process_nodes_and_edges(nodes_and_edges)
        metrics = calculate_metrics(nodes_and_edges)

        save_metrics(metrics)
