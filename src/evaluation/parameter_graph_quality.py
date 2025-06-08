import os

from evaluation.graph_quality import convert_metric_to_str, calculate_correctness, calculate_conciseness, calculate_completeness, read_nodes_or_edges, process_nodes_and_edges
from helpers.constant_helper import ATTACK_DESCRIPTIONS


def collect_nodes_and_edges():
    nodes_and_edges = {}

    for parameters in os.listdir('../../output/evaluation/parameters/'):
        nodes_and_edges[parameters] = {}

        for file in os.listdir(f'../../output/evaluation/parameters/{parameters}/nodes_and_edges/'):
            team = file.split('_')[0]
            nodes_or_edges = file.split('_')[1].split('.')[0]

            if team not in nodes_and_edges[parameters].keys():
                nodes_and_edges[parameters][team] = {}

            nodes_and_edges[parameters][team][nodes_or_edges] = read_nodes_or_edges(f'../../output/evaluation/parameters/{parameters}/nodes_and_edges/{file}')

    return nodes_and_edges


def calculate_metrics(nodes_and_edges: dict):
    metrics = {}

    for parameters in nodes_and_edges.keys():
        metrics[parameters] = {}

        for team in nodes_and_edges[parameters].keys():
            edges = nodes_and_edges[parameters][team]['edges']

            correctness = calculate_correctness(edges, ATTACK_DESCRIPTIONS[team])
            conciseness = calculate_conciseness(edges, ATTACK_DESCRIPTIONS[team].copy())
            completeness = calculate_completeness(edges, ATTACK_DESCRIPTIONS[team])

            metrics[parameters][team] = {}
            metrics[parameters][team]['correctness'] = correctness
            metrics[parameters][team]['conciseness'] = conciseness
            metrics[parameters][team]['completeness'] = completeness

    return metrics


def print_metrics(metrics: dict):
    results = {}

    for parameters, values in metrics.items():
        correctness = 0
        conciseness = 0
        completeness = 0

        for team in values.keys():
            correctness += values[team]['correctness']
            conciseness += values[team]['conciseness']
            completeness += values[team]['completeness']

        correctness = convert_metric_to_str(correctness / len(values.keys()))
        conciseness = convert_metric_to_str(conciseness / len(values.keys()))
        completeness = convert_metric_to_str(completeness / len(values.keys()))
        combined = correctness + '|||' + conciseness + '|||' + completeness

        if combined not in results.keys():
            results[combined] = []

        results[combined].append(parameters)

    print(results)


# This code is essentially a copy of the code in graph_quality.py, but calculates metrics per parameter combination instead of per modality combination
if __name__ == '__main__':
    nodes_and_edges = collect_nodes_and_edges()
    nodes_and_edges = process_nodes_and_edges(nodes_and_edges)
    metrics = calculate_metrics(nodes_and_edges)

    print_metrics(metrics)
