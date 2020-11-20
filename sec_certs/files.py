import json
import os

FILE_ERRORS_STRATEGY = 'surrogateescape'
'replace'
# FILE_ERRORS_STRATEGY = 'strict'

def search_files(folder):
    for root, dirs, files in os.walk(folder):
        yield from [os.path.join(root, x) for x in files]


def load_cert_html_file(file_name):
    with open(file_name, 'r', errors=FILE_ERRORS_STRATEGY) as f:
        try:
            whole_text = f.read()
        except UnicodeDecodeError:
            f.close()
            with open(file_name, "r", encoding="utf8", errors=FILE_ERRORS_STRATEGY) as f2:
                try:
                    whole_text = f2.read()
                except UnicodeDecodeError:
                    print('### ERROR: failed to read file {}'.format(file_name))
    return whole_text


def load_json_files(files_list):
    loaded_jsons = []
    for file_name in files_list:
        with open(file_name) as json_file:
            loaded_items = json.load(json_file)
            loaded_jsons.append(loaded_items)
            print('{} loaded, total items = {}'.format(file_name, len(loaded_items)))
    return tuple(loaded_jsons)
