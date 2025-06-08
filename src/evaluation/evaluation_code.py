# ***************************************
# This code was used for parameter tuning
# ***************************************
for sink_count in range(1, 21):
    for state_count in range(1, 21):
        for symbol_count in range(1, 21):
            if sink_count > state_count:
                print(f'[{sink_count}, {state_count}, {symbol_count}]')
                print(f'\n=== PROCESSING SPDFA PARAMETER COMBINATION [{sink_count}, {state_count}, {symbol_count}] ===')

                SINK_COUNT = sink_count
                STATE_COUNT = state_count
                SYMBOL_COUNT = symbol_count

                write_txt(f'output/evaluation/parameters/{sink_count}-{state_count}-{symbol_count}/nodes_and_edges/{team}_nodes.txt', list(nodes))
                write_txt(f'output/evaluation/parameters/{sink_count}-{state_count}-{symbol_count}/nodes_and_edges/{team}_edges.txt', list(edges))
