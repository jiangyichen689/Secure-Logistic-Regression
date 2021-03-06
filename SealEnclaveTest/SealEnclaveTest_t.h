#ifndef SEALENCLAVETEST_T_H__
#define SEALENCLAVETEST_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


void foo(char* buf, size_t len);
void generate_key_sgx();
void get_public_key(char* public_key_buffer, size_t len);
void get_secret_key(char* secret_key_buffer, size_t len);
void sigmod_sgx(char* buffer, size_t len, int trainingSize, int precision);
int check_Index();
void DecreaseNoise_SGX(char* buf, size_t len, int trainingSize, double y_initial);
void MakeConfigure_SGX(char* ConfigureBuffer, size_t len);
void AggregateRows_SGX(char* buf, size_t len, int trainingSize, int precision);
void ScaleDown_SGX(char* buf, size_t len, int trainingSize, int precision);
void HalfScaleDown_SGX(char* buf, size_t len, int trainingSize, int precision);

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
