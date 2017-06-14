#!/bin/bash

service openvswitch-switch start

# Use our custom ryu-manager script.
export PATH=/root/faucet/tests/bin:$PATH

cd /root/faucet/tests

python3 test_check_config.py
PYTHONPATH=../faucet python3 test_config.py
PYTHONPATH=..:../faucet python3 test_valve.py

PYTHONPATH=..:/root/zof python faucet_mininet_test.py -n -k
