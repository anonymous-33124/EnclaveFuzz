./sgxwallet --cb_enclave=secure_enclave.signed.so ./result/seeds -print_pcs=1 -print_coverage=1 -use_value_profile=1 -artifact_prefix=./result/crashes/ -ignore_crashes=1 -fork=1 -max_len=1000000 -max_totclear
./sgxwallet --cb_enclave=secure_enclave.signed.so ./result/seeds -print_pcs=1 -print_coverage=1 -use_value_profile=1 -artifact_prefix=./result/crashes/ -max_total_time=60 --cb_max_count=16 --cb_max_size=128 --cb_max_strlen=128 --cb_ecall_queue_size=1
./sgxwallet --cb_enclave=secure_enclave.signed.so ./result/seeds -print_pcs=1 -print_coverage=1 -use_value_profile=1 -artifact_prefix=./result/crashes/ -max_total_time=86400 --cb_max_count=16 --cb_max_size=128 --cb_max_strlen=128 --cb_ecall_queue_size=1
./sgxwallet --cb_enclave=secure_enclave.signed.so ./result/seeds -print_pcs=1 -print_coverage=1 -use_value_profile=1 -artifact_prefix=./result/crashes/ -max_total_time=86400 --cb_max_count=16 --cb_max_size=128 --cb_max_strlen=128 --cb_ecall_queue_size=1
./sgxwallet --cb_enclave=secure_enclave.signed.so ./result/seeds -print_pcs=1 -print_coverage=1 -use_value_profile=1 -artifact_prefix=./result/crashes/ -max_total_time=86400 --cb_max_count=2 --cb_max_size=64 --cb_max_strlen=64 --cb_ecall_queue_size=1