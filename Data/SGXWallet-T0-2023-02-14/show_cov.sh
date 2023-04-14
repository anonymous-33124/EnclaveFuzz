#!/usr/bin/env bash

cp /home/ramdisk/SGXWallet-allcoverage-T1-2023-02-14/result/all.profdata ./result/all.profdata
# llvm-profdata-13 merge --failure-mode=all -sparse -output=./result/all.profdata ./result/profraw/
llvm-cov-13 report ./secure_enclave.signed.so -instr-profile=./result/all.profdata -use-color

