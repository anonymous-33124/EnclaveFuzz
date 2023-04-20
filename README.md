# EnclaveFuzz
Table of Contents
- [EnclaveFuzz](#enclavefuzz)
  - [Introduction](#introduction)
  - [Transparency Note](#transparency-note)
  - [Bug Examples](#bug-examples)
    - [NULL ptr de-reference](#null-ptr-de-reference)
      - [Case 1 Uninitialized global variable](#case-1-uninitialized-global-variable)
      - [Case 2 Unchecked input pointer](#case-2-unchecked-input-pointer)
      - [Case 3 Unchecked nested pointer](#case-3-unchecked-nested-pointer)
      - [Case 4 Unchecked nested pointer](#case-4-unchecked-nested-pointer)
    - [Heap Overflow](#heap-overflow)
      - [Case 1 Unmatched buffer size](#case-1-unmatched-buffer-size)
      - [Case 2 Unchecked size](#case-2-unchecked-size)
    - [Int Overflow](#int-overflow)
      - [Case 1 Unchecked malloc size](#case-1-unchecked-malloc-size)
      - [Case 2 Unchecked size](#case-2-unchecked-size-1)
    - [Use-after-free](#use-after-free)
      - [Case 1 A naive UAF exists for over 6 years](#case-1-a-naive-uaf-exists-for-over-6-years)
      - [Case 2](#case-2)
    - [TOCTOU](#toctou)
      - [Case 1 Use of untrusted nested pointer](#case-1-use-of-untrusted-nested-pointer)
      - [Case2 Use of untrusted function pointer](#case2-use-of-untrusted-function-pointer)
    - [Stack Overflow](#stack-overflow)
      - [Case 1](#case-1)
  - [Usage of EnclaveFuzz](#usage-of-enclavefuzz)
## Introduction
EnclaveFuzz is a structure-aware fuzzing framework that extracts the trust boundary from applications and constructs fuzz harnesses for enclaves. 

Compared to previous work, EnclaveFuzz can effectively recover complex structures and perform 3-dimension fuzzing. To detect more vulnerabilities, we design a new sanitizer to detect SGX-specific vulnerabilities. Since the speed of fuzzy processing will affect the efficiency of vulnerability mining, we provide a custom SDK to speed up the fuzzing process. We applied our work to test 13 real-world open-source enclaves and found 122 bugs in 8 of them, demonstrating the effectiveness of EnclaveFuzz.

## Transparency Note
The source code of EnclaveFuzz will be open-sourced upon acceptance, including prototype implementations and testing environment to reproduce the results.


## Bug Examples
### NULL ptr de-reference

#### Case 1 Uninitialized global variable
```c
/* EDL Def. */
public void trustedEnclaveInit(uint64_t _logLevel);
public void trustedGenerateEcdsaKey (
                        [out] int *errStatus,
                        [out, count = SMALL_BUF_SIZE] char* err_string,
                        [in, count = 1] int *is_exportable,
                        [out, count = SMALL_BUF_SIZE] uint8_t* encrypted_key,
                        [out] uint64_t *enc_len,
                        [out, count = SMALL_BUF_SIZE] char * pub_key_x,
                        [out, count = SMALL_BUF_SIZE] char * pub_key_y);
```


```c++
/* ECALL trustedEnclaveInit calls enclave_init for initialization */
void trustedEnclaveInit(uint64_t _logLevel) {
    enclave_init();
}

/* curve is a global variable */
domain_parameters curve;
void enclave_init() {
    /* curve is set during Enclave initialization */
    curve = domain_parameters_init();
}


void trustedGenerateEcdsaKey(int *errStatus, char *errString, int *is_exportable,
                                uint8_t *encryptedPrivateKey, uint64_t *enc_len, char *pub_key_x, char *pub_key_y) {
                                
  /* curve is used in ECALL trustedGenerateEcdsaKey */
  mpz_mod(skey, seed, curve->p);
}
```
If ```trustedGenerateEcdsaKey``` is called before the initialization, it will trigger NULL pointer de-reference bug.

#### Case 2 Unchecked input pointer
```c
/* EDL Def. */
public void trustedGenerateEcdsaKey (
                        [out] int *errStatus,
                        [out, count = SMALL_BUF_SIZE] char* err_string,
                        [in, count = 1] int *is_exportable,
                        [out, count = SMALL_BUF_SIZE] uint8_t* encrypted_key,
                        [out] uint64_t *enc_len,
                        [out, count = SMALL_BUF_SIZE] char * pub_key_x,
                        [out, count = SMALL_BUF_SIZE] char * pub_key_y);
```

```c++
void trustedGenerateEcdsaKey(int *errStatus, char *errString, int *is_exportable,
                                uint8_t *encryptedPrivateKey, uint64_t *enc_len, char *pub_key_x, char *pub_key_y) {
    ...
    /* pointer is_exportable is not checked here */
    if ( *is_exportable ) {
        status = AES_encrypt((char *) skey_str, encryptedPrivateKey, BUF_LEN,
                             ECDSA, EXPORTABLE, enc_len);
    } ...
```
#### Case 3 Unchecked nested pointer
```c
/* EDL Def. */
public void ecall_trainer([user_check]list* sections,
                          [user_check] data* training_data, 
                          int pmem,
                          [user_check]comm_info* o_point);

```



```c
void ecall_trainer(list *sections, data *training_data, int bsize, comm_info *info)
{
    /* sections is an input pointer */
    train_mnist(sections, training_data, bsize);
}

void train_mnist(list *sections, data *training_data, int pmem)
{

    /* allocate enclave model */
    net = create_net_in(sections);
}

network *create_net_in(list *sections)
{
    node *n = sections->front;
    /* n is checked here */
    if (!n) {
        error("Config file has no sections");
    }

    section *s = (section *)n->val;
    /* ptr s is not checked here */
    list *options = s->options;
}
```


#### Case 4 Unchecked nested pointer
```c
/* EDL Def. */
public long	ecall_SSL_CTX_ctrl([user_check] SSL_CTX *ctx,int cmd, long larg, [user_check] void *parg);
```

```c
long ecall_SSL_CTX_ctrl(SSL_CTX *ctx, int cmd, long larg, void *parg) {
    return SSL_CTX_ctrl(ctx, cmd, larg, parg);
}

long
SSL_CTX_ctrl(SSL_CTX *ctx, int cmd, long larg, void *parg)
{
    // Attacker can control the function pointer
    return (ctx->method->ssl_ctx_ctrl(ctx, cmd, larg, parg));
}
```

### Heap Overflow
#### Case 1 Unmatched buffer size
Ecall ```trustedBlsSignMessage``` uses a macro to log messages. However, the size of max buffer length from EDL definition and implementation does not match.
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
```c++
/* Generated tbridge */
/* sgxwallet/secure_enclave/secure_enclave_t.c */
static sgx_status_t SGX_CDECL sgx_trustedBlsSignMessage(void* pms)
{
    ...

    if (_tmp_err_string != NULL && _len_err_string != 0) {
        ...
        /* _len_err_string is 256 here  */
        if ((_in_err_string = (char*)malloc(_len_err_string)) == NULL) {
            status = SGX_ERROR_OUT_OF_MEMORY;
            goto err;
        }

        memset((void*)_in_err_string, 0, _len_err_string);
    }
```
However, from the use point the size of ```errString``` is set as 1024
```c++
void trustedBlsSignMessage(int *errStatus, char *errString, uint8_t *encryptedPrivateKey,
                              uint64_t enc_len, char *_hashX,
                              char *_hashY, char *signature) {
    ...
    CHECK_STATUS(" error messages ");
    ...
}

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
#### Case 2 Unchecked size
```c
/* EDL Def. */
public int ecall_add_item(
    [in, string]const char* master_password, 
    [in, size=item_size]const item_t* item,
    size_t item_size
);
```

```c
int ecall_add_item(const char* master_password, const item_t* item, const size_t item_size) {
    // size of item is specified by item_size e.g. 4, and it's malloc-ed by tbirdge, but item_t is a structure that contain 300 bytes, thus *item will OOB read cand then read redzone.
    wallet->items[wallet_size] = *item;
}
```



### Int Overflow
#### Case 1 Unchecked malloc size
```c
/* EDL Def. */
public void ecall_trainer([user_check]list* sections,
                          [user_check] data* training_data, 
                          int pmem,
                          [user_check]comm_info* o_point);

```



```c
void ecall_trainer(list *sections, data *training_data, int bsize, comm_info *info)
{
    /* sections is an input pointer */
    train_mnist(sections, training_data, bsize);
}

void train_mnist(list *sections, data *training_data, int pmem)
{

    /* allocate enclave model */
    net = create_net_in(sections);
}

network *create_net_in(list *sections)
{
    /* sections->size is not checked here */
    network *net = make_network(sections->size - 1);
}

network *make_network(int n)
{
    net->n = n;
    /* CALLOC(size_t n_elements, size_t elem_size) */
    net->layers = calloc(net->n, sizeof(layer));
    ...
}
```
#### Case 2 Unchecked size
```c
/* EDL Def. */
public void ecall_ERR_error_string_n(unsigned long e, [user_check] char *buf, size_t len);
```

```c
void
ecall_ERR_error_string_n(unsigned long e, char *buf, size_t len) 
{
    ERR_error_string_n(e, buf, len);
}

void
ERR_error_string_n(unsigned long e, char *buf, size_t len)
{
    // len is not trusted and not checked
    ret = snprintf(buf, len, "error:%08lX:%s:%s:%s", e, ls, fs, rs);
}
```
### Use-after-free
#### Case 1 A naive UAF exists for over 6 years
```c
/* EDL Def. */
public void rsa_key_gen();
```


```c
void rsa_key_gen()
{
    /* free */
    EVP_PKEY_free(evp_pkey);
    /* use */
    if (evp_pkey->pkey.ptr != NULL) {
        RSA_free(keypair);
    }
}
```
#### Case 2 
```c
/*  EDL Def. */
public void ssl_conn_init(void);
public void ssl_conn_teardown(void);
public void ssl_conn_handle(long int thread_id, [in,out] thread_info_t* thread_info);
```

```c
// Attacker can call ssl_conn_init, ssl_conn_teardown and finally call ssl_conn_handle
void ssl_conn_init(void) {
  connectionHandler = new TLSConnectionHandler();
}

void ssl_conn_handle(long int thread_id, thread_info_t* thread_info) {
    // use deleted connectionHandler
    connectionHandler->handle(thread_id, thread_info);
}

void TLSConnectionHandler::handle(long int thread_id, thread_info_t *thread_info) {
    // use deleted this
    memcpy(&conf, &this->conf, sizeof(mbedtls_ssl_config));
}

void ssl_conn_teardown(void) {
    // free
    delete connectionHandler;
}
```

### TOCTOU
#### Case 1 Use of untrusted nested pointer
```c
/* EDL Def. */
public int ecall_BIO_free([user_check] BIO *a);
```

```c
int ecall_BIO_free(BIO *a) {
    return BIO_free(a);
}

// argument a is [user_check], but without enough user check
static int
file_free(BIO *a)
{
    // &a->ptr is reside in non-Enclave(untrusted) memory
    // check a->ptr
    if ((a->init) && (a->ptr != NULL)) {
        // use a->ptr, can changed by attacker
        fclose (a->ptr);
    }
}
```
#### Case2 Use of untrusted function pointer
```c
int
BIO_read(BIO *b, void *out, int outl)
{
    // $b->method resides in non-Enclave memory
    // b->method can be changed after check by attacker
	if ((b == NULL) || (b->method == NULL) || (b->method->bread == NULL))
}
```
### Stack Overflow
#### Case 1 
```c
SQLITE_PRIVATE int sqlite3BtreeOpen(...) {
  unsigned char zDbHeader[100];
  rc = sqlite3PagerReadFileheader(...,zDbHeader); // sqlite3PagerReadFileheader call unixRead, and zDbHeader is passed to pBuf
}
static int unixRead(..., void *pBuf, ...) {
  got = seekAndRead(...);
  // if got is not equal to amt or smaller than 0 
  memset(&((char*)pBuf)[got], 0, amt-got); // &pBuf[got] stack overflow
}
static int seekAndRead(...) {
  got = osRead(id->h, pBuf, cnt); // osRead call ocall_read, and get got from host
  return got;
}
```

## Usage of EnclaveFuzz
EnclaveFuzz could run in any Linux-like environment without any special requirement. Developers only need to modify the build script to use the EnclaveFuzz SDK and add some compiler/linker flags.

## Bugs found by EnclaveFuzz vs SGXFuzz

|SGX APP|Bugs Found by EnclaveFuzz|Bugs Found by SGXFuzz|
|--|--|--|
|Intel SGXSSL|2 UAF + 1 0Ptr|0|
|mbedtls-SGX|2 0Ptr + 2 UAF|1 0Ptr|
|SGX_SQLite|1 UAF + 1 StackOverflow|0|
|sgx-wallet|7 0Ptr + 3 HeapOverflow|1 0Ptr|
|wolfssl|0|0|