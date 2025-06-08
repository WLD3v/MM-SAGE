import subprocess
import os

from analysis.log_analysis import Ruleset
from helpers.constant_helper import MODALITY_COMBINATIONS
from new_graph_generation.model_learning import learn_model
from new_graph_generation.model_loading import load_models
from helpers.files import write_txt
from new_graph_generation.observable_episode_processing import create_observable_episodes
from new_graph_generation.observable_episode_sequence_processing import collect_observable_episode_sequences
from new_graph_generation.observable_sequence_processing import process_observable_sequences

from stages.observable_collection import collect_observables


# TODO: replace this after refactoring
def save_traces(team_episode_sequences):
    print('\n*** SAVING TRACES ***')

    traces = []
    symbol_set = set()
    for team, episode_sequences in team_episode_sequences.items():
        for episode_sequence in episode_sequences:
            trace = episode_sequence.to_trace()
            traces.append(trace)

            symbols = trace.split(' ')[2:]
            for symbol in symbols:
                symbol_set.add(symbol)

    path = 'output/traces/traces.txt'
    write_txt(path, [f'{len(traces)} {len(symbol_set)}'] + traces)

    print(f'Stored {len(traces)} traces to path {path}')

    return traces


def print_parameters():
    print('(1) Scope Parameters')
    print(f'HOSTS = {HOSTS}')
    print(f'MODALITIES = {MODALITIES}')
    print(f'EXPERIMENT = {EXPERIMENT}')

    print('\n(2) Data Processing Parameters')
    print(f'OBSERVABLE_DUPLICATE_WINDOW = {OBSERVABLE_DUPLICATE_WINDOW}')
    print(f'SEQUENCE_WINDOW = {SEQUENCE_WINDOW}')
    print(f'EPISODE_PAUZE = {EPISODE_PAUSE}')

    print(f'\nUSE_LABELS = {USE_LABELS}')
    print(f'RULESET = {RULESET}')

    print('\n(3) Model Learning Parameters')
    print(f'SINK_COUNT = {SINK_COUNT}')
    print(f'STATE_COUNT = {STATE_COUNT}')
    print(f'SYMBOL_COUNT = {SYMBOL_COUNT}')


def collect_data():
    print('\n*** COLLECTING OBSERVABLES ***')
    team_observables = collect_observables(HOSTS, MODALITIES, USE_LABELS, OBSERVABLE_DUPLICATE_WINDOW, RULESET)

    print('\n*** CREATING OBSERVABLE SEQUENCES ***')
    team_observable_sequences = process_observable_sequences(team_observables, SEQUENCE_WINDOW)

    print('\n*** CREATING EPISODES ***')
    team_observable_episodes = create_observable_episodes(team_observable_sequences, EPISODE_PAUSE)

    print('\n*** CREATING EPISODE SEQUENCES ***')
    team_episode_sequences = collect_observable_episode_sequences(team_observable_episodes)

    print('\n*** CREATING TRACES ***')
    save_traces(team_episode_sequences)

    return team_episode_sequences


def create_model():
    print('\n*** LEARNING S-PDFA model ***')
    learn_model(SINK_COUNT, STATE_COUNT, SYMBOL_COUNT)
    main_model, sinks_model = load_models()

    return main_model, sinks_model


def create_state_sequences(team_episode_sequences: dict):
    print('\n*** UPDATING EPISODES WITH STATE INFORMATION ***')
    for team, episode_sequences in team_episode_sequences.items():
        for episode_sequence in episode_sequences:
            symbols = episode_sequence.to_trace().split(' ')[2:]

            current_state = '0'
            states = ['0']
            main_or_sink = ['Main']
            for symbol in symbols:
                if current_state in main_model and symbol in main_model[current_state]:
                    transition = main_model[current_state]
                    next_state = main_model[current_state][symbol]
                    current_state = next_state
                    states.append(next_state)
                    main_or_sink.append('Main')
                elif current_state in sinks_model and symbol in sinks_model[current_state]:
                    transition = sinks_model[current_state]
                    next_state = sinks_model[current_state][symbol]
                    current_state = next_state
                    states.append(next_state)
                    main_or_sink.append('Sink')
                else:
                    current_state = '-1'
                    print("ERROR")

            states.reverse()
            main_or_sink.reverse()

            # Update episodes with their state
            for index, episode in enumerate(episode_sequence.episodes):
                episode.state_id = states[index]
                episode.main_or_sink = main_or_sink[index]


def create_attack_graphs(team_episode_sequences: dict):
    print('\n*** CREATING NODES AND EDGES ***')
    for team, episode_sequences in team_episode_sequences.items():
        nodes_file_path = f'output/nodes_and_edges/{team}_nodes.txt'
        edges_file_path = f'output/nodes_and_edges/{team}_edges.txt'

        nodes = set()
        edges = []
        for episode_sequence in episode_sequences:

            previous_node = None
            for episode in episode_sequence.episodes:
                node = f'{episode.category}-{episode.state_id}, {episode.main_or_sink}'

                if previous_node is not None:
                    edges.append(f'{previous_node.split(',')[0]}-->{node.split(',')[0]}')

                nodes.add(node)
                previous_node = node

        write_txt(nodes_file_path, list(nodes))
        write_txt(edges_file_path, list(edges))

        if EXPERIMENT == 1:
            if USE_LABELS:
                evaluation_nodes_file_path = f'output/evaluation/quality/labels/{'-'.join(MODALITIES)}/nodes_and_edges/{team}_nodes.txt'
                evaluation_edges_file_path = f'output/evaluation/quality/labels/{'-'.join(MODALITIES)}/nodes_and_edges/{team}_edges.txt'
            else:
                evaluation_nodes_file_path = f'output/evaluation/quality/{RULESET}/{'-'.join(MODALITIES)}/nodes_and_edges/{team}_nodes.txt'
                evaluation_edges_file_path = f'output/evaluation/quality/{RULESET}/{'-'.join(MODALITIES)}/nodes_and_edges/{team}_edges.txt'

            write_txt(evaluation_nodes_file_path, list(nodes))
            write_txt(evaluation_edges_file_path, list(edges))

    print('\n*** CREATING ATTACK GRAPHS ***')
    command = ['wsl', 'python3', 'src/graph_gen.py']
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)

    if EXPERIMENT == 1:
        if USE_LABELS:
            evaluation_graph_directory = f'output/evaluation/quality/labels/{'-'.join(MODALITIES)}/graphs'

            if not os.path.exists(evaluation_graph_directory):
                os.makedirs(evaluation_graph_directory)

            os.rename(f'output/graphs/all_ag.png', f'{evaluation_graph_directory}/all_ag.png')
        else:
            evaluation_graph_directory = f'output/evaluation/quality/{RULESET}/{'-'.join(MODALITIES)}/graphs'

            if not os.path.exists(evaluation_graph_directory):
                os.makedirs(evaluation_graph_directory)

            os.rename(f'output/graphs/all_ag.png', f'{evaluation_graph_directory}/all_ag.png')

    assert result.returncode == 0, 'Graph generation failed'


# Scope parameters
HOSTS = ['intranet_server', 'monitoring']
MODALITIES = ['logs', 'wazuh', 'suricata', 'aminer']
EXPERIMENT = 0

# Data processing parameters
OBSERVABLE_DUPLICATE_WINDOW = 1.0
SEQUENCE_WINDOW = 60.0 * 60 * 2
EPISODE_PAUSE = 17.5

USE_LABELS = False
RULESET = Ruleset.STRICT

# Model learning parameters
SINK_COUNT = 2
STATE_COUNT = 1
SYMBOL_COUNT = 1

if __name__ == '__main__':
    # Basic usage of MM-SAGE, generates attack graphs based on the provided parameters
    if EXPERIMENT == 0:
        print('*** EXECUTING MM-SAGE WITH PARAMETERS ***')
        print_parameters()

        team_episode_sequences = collect_data()
        main_model, sinks_model = create_model()
        create_state_sequences(team_episode_sequences)
        create_attack_graphs(team_episode_sequences)

    # For evaluation purposes, creates attack graphs for each possible modality combination
    elif EXPERIMENT == 1:
        for modalities in MODALITY_COMBINATIONS:
            MODALITIES = modalities

            print('*** EXECUTING MM-SAGE WITH PARAMETERS ***')
            print_parameters()

            team_episode_sequences = collect_data()
            main_model, sinks_model = create_model()
            create_state_sequences(team_episode_sequences)
            create_attack_graphs(team_episode_sequences)
