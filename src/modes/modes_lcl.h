/**
 * @file modes_lcl.h
 * @author Weijie Li
 * @brief 
 * @version 0.1
 * @date 2018-10-31
 * 
 * @copyright Copyright (c) 2018
 * 
 */

#ifndef _WBCRYPTO_MODES_H_
#define _WBCRYPTO_MODES_H_

#include "crypto/modes.h"

static void OPENSSL_cleanse(void *ptr, size_t len);

/*
 * WBCRYPTO_memcmp returns zero iff the |len| bytes at |a| and |b| are equal.
 * It takes an amount of time dependent on |len|, but independent of the
 * contents of |a| and |b|. Unlike memcmp, it cannot be used to put elements
 * into a defined order as the return value when a != b is undefined, other
 * than to be non-zero.
 */
static int WBCRYPTO_memcmp(const void * in_a, const void * in_b, size_t len);

static void WBCRYPTO_free(void *ptr, const char *file, int line);

static void WBCRYPTO_clear_free(void *ptr, size_t num, const char *file, int line);

static void *WBCRYPTO_malloc(size_t num, const char *file, int line);



#ifndef OPENSSL_FILE
# ifdef OPENSSL_NO_FILENAMES
#  define OPENSSL_FILE ""
#  define OPENSSL_LINE 0
# else
#  define OPENSSL_FILE __FILE__
#  define OPENSSL_LINE __LINE__
# endif
#endif

// #  define OPENSSL_FILE __FILE__
// #  define OPENSSL_LINE __LINE__


# define OPENSSL_clear_free(addr, num) \
        WBCRYPTO_clear_free(addr, num, OPENSSL_FILE, OPENSSL_LINE)
# define OPENSSL_malloc(num) \
        WBCRYPTO_malloc(num, OPENSSL_FILE, OPENSSL_LINE)

# define OPENSSL_free(addr) \
        WBCRYPTO_free(addr, OPENSSL_FILE, OPENSSL_LINE)

# define OSSL_NELEM(x)    (sizeof(x)/sizeof((x)[0]))



/*******************  source *******************/


typedef void *(*memset_t)(void *, int, size_t);

static volatile memset_t memset_func = memset;



static void OPENSSL_cleanse(void *ptr, size_t len)
{
    memset_func(ptr, 0, len);
}

static int WBCRYPTO_memcmp(const void * in_a, const void * in_b, size_t len)
{
    size_t i;
    const volatile unsigned char *a = in_a;
    const volatile unsigned char *b = in_b;
    unsigned char x = 0;

    for (i = 0; i < len; i++)
        x |= a[i] ^ b[i];

    return x;
}

static void WBCRYPTO_free(void *str, const char *file, int line)
{
    free(str);
}

static void WBCRYPTO_clear_free(void *str, size_t num, const char *file, int line)
{
    if (str == NULL)
        return;
    if (num)
        OPENSSL_cleanse(str, num);
    WBCRYPTO_free(str, file, line);
}

static void *WBCRYPTO_malloc(size_t num, const char *file, int line)
{
    void *ret = NULL;

    if (num == 0)
        return NULL;

    (void)(file); (void)(line);
    ret = malloc(num);

    return ret;
}





#endif //_WBCRYPTO_MODES_H_