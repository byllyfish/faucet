#!/bin/bash

echo "========== Checking IPv4/v6 localhost is up ====="
sysctl -w net.ipv6.conf.all.disable_ipv6=0
ping6 -c 1 ::1 || exit 1
ping -c 1 127.0.0.1 || exit 1

echo "========== Starting OVS ========================="
service openvswitch-switch start
ovs-vsctl show || exit 1

# enable fast reuse of ports.
sysctl -w net.netfilter.nf_conntrack_tcp_timeout_time_wait=10
sysctl -w net.ipv4.tcp_tw_recycle=1
sysctl -w net.ipv4.tcp_tw_reuse=1
# minimize TCP connection timeout so application layer timeouts are quicker to test.
sysctl -w net.ipv4.tcp_syn_retries=4


# Use our custom ryu-manager script.
export PATH=/root/faucet/tests/bin:$PATH

echo "========== Running zof-faucet unit tests =========="
cd /root/faucet
python3 -m unittest discover zof_test

cd /root/faucet/tests
python3 test_check_config.py
PYTHONPATH=../faucet python3 test_config.py
PYTHONPATH=..:../faucet python3 test_valve.py

echo "========== Running zof-faucet system tests =========="
PYTHONPATH=..:/root/zof python faucet_mininet_test.py -n -k "$@"
