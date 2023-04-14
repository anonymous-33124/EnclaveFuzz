#!/usr/bin/env bash

set -ex

kill -9 $(cat fuzz.pid)
rm fuzz.pid
