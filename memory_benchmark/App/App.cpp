#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif


# define MAX_PATH FILENAME_MAX

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <pwd.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <pthread.h>


#include <fcntl.h>
#include <sys/ioctl.h>
#include <chrono>
#include <sched.h>
#include <iostream>
#include <sstream>
#include <fstream>
#include "../include/common.h"

#include <assert.h>
#include <stdlib.h>
#include <pthread.h>


#include <algorithm>
#include <atomic>
#include <cstring>  // for memset
#include <cstdint>
#include <numeric>
#include <string>
#include <vector>

#include <thread>
#include <mutex>
#include <condition_variable>



#include "App.h"


#include "sgx_urts.h"
#include "Enclave_u.h"
#include <sgx_trts.h>

#define SDK_ECALL_COST 9400
#define BENCHMARK_DURATION 20
#define NODE_SIZE 256
#define NUMBER_TRIALS 1000
#define CPU_1 0
#define CPU_2 28

using namespace std;

int numa_flag = 0;
int rnd_flag = 0;
size_t num_threads = 1;

uint64_t size_mb = 10;  //default size is 10 MB
uint64_t number_nodes;




sgx_enclave_id_t globalEnclaveID;
sgx_enclave_id_t m_enclaveID;
int              m_sgxDriver;


pthread_barrier_t barrier;
pthread_mutex_t lock1;


vector<uint64_t> avgs;




typedef sgx_status_t (*EcallFunction)(sgx_enclave_id_t, void* );




inline __attribute__((always_inline))  uint64_t rdtscp(void)
{
        unsigned int low, high;
        asm volatile("rdtscp" : "=a" (low), "=d" (high));
        return low | ((uint64_t)high) << 32;
}


struct Node {
   Node* next{nullptr};
   uint64_t data{0};     // just to ensure that it will not be outcompiled
   uint64_t padding[(NODE_SIZE-8-8)/8];  // (64 -8-8)/8 (8 is lengtho of uint64)
}__attribute__ ((aligned (NODE_SIZE)));



typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;





/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};


/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
        printf("Error: Unexpected error occurred.\n");
}



/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate 
     * the input string to prevent buffer overflow. 
     */
    printf("%s", str);
}


void pin(int core)
{
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(core, &mask);
    if (sched_setaffinity(0, sizeof(cpu_set_t), &mask) == -1)
    {
        perror("sched_setaffinity");
        abort();
    }
}


uint64_t rnd(uint64_t& seed)
{
   uint64_t x = seed;
   x ^= x >> 12;      // a
   x ^= x << 25;      // b
   x ^= x >> 27;      // c
   seed = x;
   return x * 0x2545F4914F6CDD1D;
}

void random_shuffle(std::vector<uint64_t>& nodes_idxs)
{
   auto n = nodes_idxs.size();
   uint64_t seed = 19650218ULL;
   for (uint64_t i = n - 1; i > 0; --i) {
      std::swap(nodes_idxs[i], nodes_idxs[rnd(seed) % (i + 1)]);
   }
}

void shuffleList(Node*& root, uint64_t number_nodes, bool shuffle)
{
   // -------------------------------------------------------------------------------------
   // create help vector of idx
   std::vector<uint64_t> node_idxs(number_nodes - 1);  // one less because we do not start at 0 -> root should stay root
   std::iota(std::begin(node_idxs), std::end(node_idxs), 1);
   if (shuffle)
      random_shuffle(node_idxs);
   // -------------------------------------------------------------------------------------
   uint64_t counter = 0;
   auto* prev = root;
   for (auto& idx : node_idxs) {
      prev->next = &root[idx];
      prev->data = counter++;
      prev = prev->next;
   }
}


void inline measured_loop(Node* current){

    volatile uint64_t result = 0 ;
    volatile uint64_t counter = 0 ;

    while (current) {
        result += current->data;
        current = current->next;
        counter++;
    }
}



void* test_trusted_memory(void* arg)
{
    
    sgx_status_t ecall_status;
    int tid = *((int *) arg);
    
    


    pin(CPU_1 + tid);





    globalEnclaveID = m_enclaveID;        
    const uint16_t requestedCallID = 0;

        
    
    
    preallocate_ecall(m_enclaveID,&number_nodes,&rnd_flag);
    
    
    if (numa_flag)  pin(CPU_2+tid);    //pin to numa socket 1




    // add a barrier here
    pthread_barrier_wait(&barrier);

    uint64_t t = 0 ;
    uint64_t result = 0;



    unsigned int low, high;
    unsigned int low1, high1;
    int64_t    start_time       = 0;
    uint64_t    end_time         = 0;
    uint64_t average = 0;
    uint64_t measurements[NUMBER_TRIALS];


    for (size_t i = 0 ; i < NUMBER_TRIALS ; i++) 
    {


        //this is taken from intel's microbenchmarking guide
        asm volatile ("CPUID\n\t"
            "RDTSC\n\t"
            "mov %%edx, %0\n\t"
            "mov %%eax, %1\n\t": "=r" (high), "=r" (low)::
            "%rax", "%rbx", "%rcx", "%rdx");
        ecall_status = custom_ecall(m_enclaveID,&result);
        asm volatile("RDTSCP\n\t"
            "mov %%edx, %0\n\t"
            "mov %%eax, %1\n\t"
            "CPUID\n\t": "=r" (high1), "=r" (low1)::
            "%rax", "%rbx", "%rcx", "%rdx");
                    
        start_time = low | ((uint64_t)high) << 32;
        end_time = low1 | ((uint64_t)high1) << 32;
        

        t = (end_time - start_time - SDK_ECALL_COST)/number_nodes;
        //t = end_time - start_time;
        average += t;
        measurements[i] = t;

        if (ecall_status != SGX_SUCCESS) {
                printf("Ecall AEX \n");
                exit(EXIT_FAILURE);
            }



    }
    
    



    average /= NUMBER_TRIALS;
    sort(measurements, measurements + NUMBER_TRIALS);



    pthread_mutex_lock(&lock1);
    avgs.push_back(average);
    cout << tid << " : " << result << endl ;
    pthread_mutex_unlock(&lock1);
    return (void*) NULL;
    
}


void* test_untrusted_memory(void* arg){


    int tid = *((int *) arg);

    

    Node* root;
    Node* node;



    if (sizeof(Node) != NODE_SIZE) {
        throw std::logic_error("Node size wrong" + std::to_string(sizeof(Node)));
        }
    
    root = new Node[number_nodes + 1];


    
    node = root;

    uint64_t n = ((uintptr_t)node) % NODE_SIZE;

    if (n != 0) {
        char* p = (char*)node;
        p = p + (NODE_SIZE - n);
        node = (Node*)p;
    }

    if (((uintptr_t)node) % 64 != 0) {
        throw std::logic_error("Not CL aligned " + std::to_string(((uintptr_t)node) % 64));
    }


    shuffleList(node, number_nodes, rnd_flag);



    pthread_barrier_wait(&barrier);

    if (numa_flag)  pin(CPU_2 + tid);


    unsigned int low, high;
    unsigned int low1, high1;
    uint64_t    start_time       = 0;
    uint64_t    end_time         = 0;
    uint64_t measurements[NUMBER_TRIALS];
    uint64_t average = 0;
    
    
    
    
    
    uint64_t t = 0 ;
    uint64_t counter = 0;
    uint64_t result = 0;


    
    for (size_t i ; i < NUMBER_TRIALS ; i++) 
    {
        auto* current = node;

    
        //this is taken from intel's microbenchmarking guide
        asm volatile ("CPUID\n\t"
            "RDTSC\n\t"
            "mov %%edx, %0\n\t"
            "mov %%eax, %1\n\t": "=r" (high), "=r" (low)::
            "%rax", "%rbx", "%rcx", "%rdx");

        
        measured_loop(current);


        asm volatile("RDTSCP\n\t"
            "mov %%edx, %0\n\t"
            "mov %%eax, %1\n\t"
            "CPUID\n\t": "=r" (high1), "=r" (low1)::
            "%rax", "%rbx", "%rcx", "%rdx");
                    
        start_time = low | ((uint64_t)high) << 32;
        end_time = low1 | ((uint64_t)high1) << 32;


        result++;
        t = (end_time - start_time)/number_nodes;
        average += t;
        measurements[i] = t;
    }
        
    
    average /= NUMBER_TRIALS;
    sort(measurements, measurements + NUMBER_TRIALS);



    pthread_mutex_lock(&lock1);
    avgs.push_back(average);
    pthread_mutex_unlock(&lock1);
    

    return (void*) NULL;

}



void run(size_t num_threads) {

    pthread_t tids[num_threads] = {};


    if (pthread_barrier_init(&barrier, NULL, num_threads) != 0) {
        cout << "\n barrier init failed" << endl; 
        return;
    }


    
    if (pthread_mutex_init(&lock1, NULL) != 0) {
        cout << "\n mutex init failed" << endl; 
        return;
    }


    
   for (int i = 0; i < num_threads; i++) {

    int *arg = (int*)malloc(sizeof(*arg));

    if ( arg == NULL ) {
        fprintf(stderr, "Couldn't allocate memory for thread.\n");
        exit(EXIT_FAILURE);
    }

    *arg = i;
    
    pthread_create(tids+i, NULL, &test_trusted_memory,arg);
    
    }

    for (int i = 0; i < num_threads; i++) pthread_join(tids[i], NULL);




    cout << "Average latency per thread :" << endl;

    for (auto i: avgs) {
        cout << i << "  ";
    }

    cout << endl;

    float average =  1.0 * accumulate(avgs.begin(), avgs.end(), 0LL) / avgs.size();

    cout << "Average latency : "<< average << endl;

    pthread_mutex_destroy(&lock1);
    pthread_barrier_destroy(&barrier);

}




/* Initialize the enclave:
    *   Step 1: try to retrieve the launch token saved by last transaction
    *   Step 2: call sgx_create_enclave to initialize an enclave instance
    *   Step 3: save the launch token if it is updated
    */
int initialize_enclave(void) {
    char token_path[MAX_PATH] = {'\0'};
    sgx_launch_token_t token = {0};
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    int updated = 0;
    
    /* Step 1: try to retrieve the launch token saved by last transaction 
        *         if there is no token, then create a new one.
        */
    /* try to get the token saved in $HOME */
    const char *home_dir = getpwuid(getuid())->pw_dir;
    
    if (home_dir != NULL && 
        (strnlen(home_dir,MAX_PATH)+strlen("/")+sizeof(TOKEN_FILENAME)+1) <= MAX_PATH) {
        /* compose the token path */
        strncpy(token_path, home_dir, strnlen(home_dir,MAX_PATH));
        strncat(token_path, "/", strlen("/"));
        strncat(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME)+1);
    } else {
        /* if token path is too long or $HOME is NULL */
        strncpy(token_path, TOKEN_FILENAME, sizeof(TOKEN_FILENAME));
    }
    
    FILE *fp = fopen(token_path, "rb");
    if (fp == NULL && (fp = fopen(token_path, "wb")) == NULL) {
        printf("Warning: Failed to create/open the launch token file \"%s\".\n", token_path);
    }
    
    if (fp != NULL) {
        /* read the token from saved file */
        size_t read_num = fread(token, 1, sizeof(sgx_launch_token_t), fp);
        if (read_num != 0 && read_num != sizeof(sgx_launch_token_t)) {
            /* if token is invalid, clear the buffer */
            memset(&token, 0x0, sizeof(sgx_launch_token_t));
            printf("Warning: Invalid launch token read from \"%s\".\n", token_path);
        }
    }
    
    /* Step 2: call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */

    cout << "Creating Enclave." << endl;
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &m_enclaveID, NULL);
    if (ret != SGX_SUCCESS) {
        printf("sgx_create_enclave returned 0x%x\n", ret);
        print_error_message(ret);
        if (fp != NULL) fclose(fp);
        return -1;
    }
    
    cout << "Enclave Creation successful. \n" << endl;
    /* Step 3: save the launch token if it is updated */
    if (updated == FALSE || fp == NULL) {
        /* if the token is not updated, or file handler is invalid, do not perform saving */
        if (fp != NULL) fclose(fp);
        return 0;
    }
    
    /* reopen the file with write capablity */
    fp = freopen(token_path, "wb", fp);
    if (fp == NULL) return 0;
    size_t write_num = fwrite(token, 1, sizeof(sgx_launch_token_t), fp);
    if (write_num != sizeof(sgx_launch_token_t))
        printf("Warning: Failed to save launch token to \"%s\".\n", token_path);
    fclose(fp);
    printf("line: %d\n", __LINE__ );
    return 0;
}





/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{

    //control the testing with parameters
    (void)(argc);
    (void)(argv);
    int opt;

    while ((opt = getopt(argc, argv, "nrs:t:")) != -1) {
        switch (opt) {
            case 'n':
                numa_flag = 1;
                continue;
            
            case 'r':
                rnd_flag = 1;
                continue;

            case 's':
                size_mb = atoi(optarg);
                continue;

            case 't':
                num_threads = atoi(optarg);
                continue;
            }
    };

    number_nodes = (size_mb) * 1e6 / sizeof(Node);


    pin(CPU_1);    //pin to numa socket 0


    m_enclaveID = 0;

    if( initialize_enclave() < 0){
        printf("Enclave init failed.\n");
        exit(EXIT_FAILURE);
        
    }

    run(num_threads);

    sgx_destroy_enclave( m_enclaveID );
    return 0;
}

