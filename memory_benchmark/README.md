# sgx_bench
benchmarking memory access latencies inside intel sgx enclaves.


### Prerequisites
intel sgx sdk and psw (https://github.com/intel/linux-sgx)





### Build and run
`source /opt/intel/sgxsdk/environment`
`./build_sign.sh; ./benchmark_sgx -n -r -s 100`
`./build_sign.sh; numactl --membind=1 -C 30 ./benchmark_sgx -n -r -s 100`

program options:
-n :cross numa 
-r :random walk
-s <size of the buffer in MB> 


### Build in debug mode
`make SGX_DEBUG=1 SGX_MODE=SW`
`sgx-gdb bencgmark_sgx`



The main benchmark function is at App/App.cpp: Benchmarker::Run()
The round trip time of calls is measured in cycles, using RDTSCP insturction. 
NOTE: the file `spinlock.c` is taken from Intel's SGX SDK repository at (https://github.com/01org/linux-sgx)
