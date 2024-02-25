#include "Enclave_u.h"
#include <errno.h>

typedef struct ms_custom_ecall_t {
	uint64_t* ms_result;
} ms_custom_ecall_t;

typedef struct ms_preallocate_ecall_t {
	uint64_t* ms_number_nodes;
	int* ms_rnd;
} ms_preallocate_ecall_t;

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

static sgx_status_t SGX_CDECL Enclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string(ms->ms_str);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[1];
} ocall_table_Enclave = {
	1,
	{
		(void*)Enclave_ocall_print_string,
	}
};
sgx_status_t custom_ecall(sgx_enclave_id_t eid, uint64_t* result)
{
	sgx_status_t status;
	ms_custom_ecall_t ms;
	ms.ms_result = result;
	status = sgx_ecall(eid, 0, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t preallocate_ecall(sgx_enclave_id_t eid, uint64_t* number_nodes, int* rnd)
{
	sgx_status_t status;
	ms_preallocate_ecall_t ms;
	ms.ms_number_nodes = number_nodes;
	ms.ms_rnd = rnd;
	status = sgx_ecall(eid, 1, &ocall_table_Enclave, &ms);
	return status;
}

sgx_status_t empty_ecall(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 2, &ocall_table_Enclave, NULL);
	return status;
}

