import json
import os


def read_json(path: str):
    with open(path, 'r') as file:
        return json.load(file)


def read_json_lines(path: str):
    with open(path, 'r') as file:
        return [json.loads(line) for line in file.readlines()]


def write_json(path: str, data: list):
    os.makedirs('/'.join(path.split('/')[:-1]), exist_ok=True)

    with open(path, 'w') as file:
        json.dump(data, file, indent=4)


def read_dict_value(data: dict, keys: list, default):
    for key in keys:
        if key in data:
            data = data[key]
        else:
            return default

    return data
