#!/bin/bash
./bitcoind -testnet stop
sleep 1
[ -e ~/.bitcoin/testnet3/bitcoind.pid ] && kill `cat cat ~/.bitcoin/testnet3/bitcoind.pid`
./bitcoind -testnet -daemon
sleep 13 
./bitcoind -testnet getinfo
