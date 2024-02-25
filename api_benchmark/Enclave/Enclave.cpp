#include <assert.h>
#include <stdlib.h>
#include <algorithm>
#include <atomic>
#include <cstring>  // for memset
#include <cstdint>
#include <numeric>
#include <string>
#include <vector>



#include "Enclave_t.h"  // structs defined in .edl file etc
#include <sgx_trts.h>  // trusted runtime system, usually always required





void custom_ecall(uint64_t* result){

   *result = 0;

}


void empty_ecall(){
   return ;
   }





////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void printf(const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}