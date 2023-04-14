#!/usr/bin/env bash

set -ex

LLVM_PROFILE_FILE="./result/profraw/%p" nohup ./sgx-wallet --cb_enclave=enclave.signed.so ./result/seeds -print_pcs=1 -print_coverage=1 -use_value_profile=1 -artifact_prefix=./result/crashes/ $@ >> coverage_exp.log 2>&1 & 
fuzz_pid=$!
echo $fuzz_pid > fuzz.pid
echo "./sgx-wallet --cb_enclave=enclave.signed.so ./result/seeds -print_pcs=1 -print_coverage=1 -use_value_profile=1 -artifact_prefix=./result/crashes/ $@" >> fuzz.cmd
ln -s /tmp/libFuzzerTemp.FuzzWithFork$fuzz_pid.dir ./libFuzzerTemp
tail -f coverage_exp.log
