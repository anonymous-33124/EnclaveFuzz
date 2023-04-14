#!/usr/bin/env bash

set -ex

LLVM_PROFILE_FILE="/home/ramdisk/SGXWallet-allcoverage-T1-2023-02-14/result/profraw/%p" nohup ./sgxwallet --cb_enclave=secure_enclave.signed.so ./result/seeds -print_pcs=1 -print_coverage=1 -use_value_profile=1 -artifact_prefix=./result/crashes/ $@ >> coverage_exp.log 2>&1 & 
fuzz_pid=$!
echo $fuzz_pid > fuzz.pid
echo "./sgxwallet --cb_enclave=secure_enclave.signed.so ./result/seeds -print_pcs=1 -print_coverage=1 -use_value_profile=1 -artifact_prefix=./result/crashes/ $@" >> fuzz.cmd
ln -s /tmp/libFuzzerTemp.FuzzWithFork$fuzz_pid.dir ./libFuzzerTemp
tail -f coverage_exp.log
