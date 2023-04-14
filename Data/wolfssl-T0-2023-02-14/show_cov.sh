#!/usr/bin/env bash

llvm-profdata-13 merge --failure-mode=all -sparse -output=./result/all.profdata ./result/profraw/
llvm-cov-13 report ./Wolfssl_Enclave.signed.so -instr-profile=./result/all.profdata -use-color
