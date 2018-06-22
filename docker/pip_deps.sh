#!/bin/bash

FAUCETHOME=`dirname $0`/..
PIPARGS=$*

for p in pip3 ; do
  for r in requirements.txt docs/requirements.txt ; do
    $FAUCETHOME/docker/retrycmd.sh "$p install -q --upgrade $PIPARGS -r $FAUCETHOME/$r" || exit 1
  done
done

for p in pip pip3 ; do
  for r in test-requirements.txt ; do
    $FAUCETHOME/docker/retrycmd.sh "$p install -q --upgrade $PIPARGS -r $FAUCETHOME/$r" || exit 1
  done
done
