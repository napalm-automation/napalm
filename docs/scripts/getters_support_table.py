#!/usr/bin/env python

"""Something."""
import json
from collections import defaultdict

from jinja2 import Environment, FileSystemLoader


SUPPORTED_NOS = ['eos', 'iosxr']
FILE = 'scripts/nosetests-{os}.json'
OUTPUT_FILE = 'support/_include/getters_support_table.rst'


def _get_test_results(nos):
    with open(FILE.format(os=nos), mode='r') as f:
        return json.loads(f.read())


def _write_results_to_disk(results):
    env = Environment(loader=FileSystemLoader('scripts/'))
    template = env.get_template('getters_support_table.j2')
    text = template.render(results=results, nos=sorted(SUPPORTED_NOS),
                           methods=sorted(results.keys()))

    with open(OUTPUT_FILE, mode='w') as f:
        f.write(text.encode('utf-8'))


def main():
    """Process."""
    results = defaultdict(dict)
    for nos in SUPPORTED_NOS:
        test_results = _get_test_results(nos)
        for testcase in test_results['modules'][0]['testcases']:
            if testcase['result'] == 'success':
                result = 'success'
            else:
                result = 'not_implemented' if testcase['error']['message'] == 'NotImplementedError'\
                                           else 'broken'
            method_name = testcase['name'].replace('test_', '')
            results[method_name][nos] = result

    _write_results_to_disk(results)


if __name__ == "__main__":
    main()
