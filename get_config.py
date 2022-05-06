from json import load


def get_config(value):
    with open('config.json','r') as f:
        result=load(f)[value]
    return result