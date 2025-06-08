import graphviz

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

        duplicate_edges.append(edge)

        processed_edges.append(edge)

    return processed_edges

print('\nGenerating attack graphs!')
teams = ['fox', 'harrison', 'russellmitchell', 'santos', 'shaw', 'wardbeck', 'wheeler', 'wilson']
colors = [
    "red",
    "blue",
    "green",
    "orange",
    "purple",
    "cyan",
    "magenta",
    "yellow"
]
# dot.edge('A', 'B', color='red')

total_nodes = set()
total_edges = []

for index, team in enumerate(teams):
    nodes_file_path = f'output/nodes_and_edges/{team}_nodes.txt'
    edges_file_path = f'output/nodes_and_edges/{team}_edges.txt'

    nodes = []
    with open(nodes_file_path) as file:
        for line in file.readlines():
            nodes.append(line.replace('\n', ''))

    edges = []
    with open(edges_file_path) as file:
        for line in file.readlines():
            edges.append(line.replace('\n', ''))


    edges = process_edges(nodes, edges)

    filename = f'{team}_ag'
    dot = graphviz.Digraph(filename=filename)

    for node in nodes:
        name = node.split(',')[0]
        main_or_sink = node.split(',')[1]
        main_or_sink = main_or_sink.replace(' ', '')
        total_nodes.add((name, main_or_sink))

        if main_or_sink == 'Main':
            dot.node(name, name)
        elif main_or_sink == 'Sink':
            dot.node(name, name, style='dotted')
        else:
            print('Whoops!')

    for edge in edges:
        # Ignore loops
        # TODO: ignore duplicate edges (keeping in mind color)
        if edge.split('-->')[0] == edge.split('-->')[1]:
            continue

        dot.edge(edge.split('-->')[0], edge.split('-->')[1])
        total_edges.append((edge.split('-->')[0], edge.split('-->')[1], colors[index]))

    print('rending to output/graphs')
    dot.render(directory='output/graphs', format='png')

filename = 'all_ag'
dot_all = graphviz.Digraph(filename=filename)
for node in total_nodes:
    name = node[0]
    main_or_sink = node[1]

    if main_or_sink == 'Main':
        dot_all.node(name, name)
    elif main_or_sink == 'Sink':
        dot_all.node(name, name, style='dotted')
    else:
        print('Whoops!')

for edge in total_edges:
    dot_all.edge(edge[0], edge[1], color=edge[2])

dot_all.attr(splines='true', concentrate='false')
dot_all.render(directory='output/graphs', format='png')

