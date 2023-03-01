# EnclaveFuzz

## Case Study 1 NULL ptr de-reference
```c++
void trustedGenerateEcdsaKey(int *errStatus, char *errString, int *is_exportable,
                                uint8_t *encryptedPrivateKey, uint64_t *enc_len, char *pub_key_x, char *pub_key_y) {
                                
  
  // curve is a global variable
  mpz_mod(skey, seed, curve->p);
}


void enclave_init() {

    try {

        ...
        /* curve is set during Enclave initialization */
        curve = domain_parameters_init();
        LOG_INFO("Initing curve domain");
        domain_parameters_load_curve(curve, secp256k1);
    } 
    ...
}
```
However, if ```trustedGenerateEcdsaKey``` is called before the initialization, it will trigger NULL ptr de-reference bug.


## Case Study 2 Heap OOB
Ecall ```trustedBlsSignMessage``` uses a macro to log messages. However, the size of max buffer length does not match.
From the EDL file, the length of err_string is 256.
```c
/* EDL Def. */
#define TINY_BUF_SIZE 256
public void trustedBlsSignMessage (
                        [out] int *errStatus,
                        [out, count = TINY_BUF_SIZE] char* err_string,
                        [in, count = TINY_BUF_SIZE] uint8_t* encrypted_key,
                        uint64_t enc_len,
                        [in, string] char* hashX ,
                        [in, string] char* hashY,
                        [out, count = SMALL_BUF_SIZE] char* signature);

```
The tBridge will malloc 256bytes for ```_in_err_string```.
```
/* Generated tbridge */
/* sgxwallet/secure_enclave/secure_enclave_t.c */
static sgx_status_t SGX_CDECL sgx_trustedBlsSignMessage(void* pms)
{
    ...

    if (_tmp_err_string != NULL && _len_err_string != 0) {
        if ( _len_err_string % sizeof(*_tmp_err_string) != 0)
        {
            status = SGX_ERROR_INVALID_PARAMETER;
            goto err;
        }
        /* _len_err_string is 256 here  */
        if ((_in_err_string = (char*)malloc(_len_err_string)) == NULL) {
            status = SGX_ERROR_OUT_OF_MEMORY;
            goto err;
        }

        memset((void*)_in_err_string, 0, _len_err_string);
    }
```
However, from the use point the size of ```errString``` is set as 1024
```
/* the BUF_LEN is 1024 here */

#define CHECK_STATUS(__ERRMESSAGE__) if (status != SGX_SUCCESS) { \
LOG_ERROR(__FUNCTION__); \
snprintf(errString, BUF_LEN, "failed with status %d : %s",  status,  __ERRMESSAGE__); \
LOG_ERROR(errString); \
*errStatus = status; \
goto clean; \
};

```
If the length of error message is larger than 256, it may lead to overflow.

