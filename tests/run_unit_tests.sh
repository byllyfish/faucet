#!/bin/bash

MINCOVERAGE=91

coverage erase || exit 1

for i in  unit/test_*py integration/experimental_api_test_app.py; do
    echo "unit test: $i"
    PYTHONPATH=.. coverage run -a --source ../faucet $i || exit 1
done
coverage report -m --fail-under=$MINCOVERAGE || exit 1
