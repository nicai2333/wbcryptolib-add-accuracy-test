#ifndef WBCRYPTO_INTERNAL_MACROS_H_
#define WBCRYPTO_INTERNAL_MACROS_H_

// INTERNAL MACROS TO SPEED UP DEVELOPMENT
// DO NOT INCLUDE THEM IN FILES OTHER THAN WBCRYPTO'S C SOURCE!

//throw(save ret and goto cleanup) on non-zero
//this is encouraged to use in wbcrypto instead of the internal mbedtls_mpi_chk macro
#define THROW_ONNZ(func)       \
    do                           \
    {                            \
        if( ( ret = (func) ) != 0 ) \
            goto cleanup;        \
    } while( 0 )

//throw(save ret and goto cleanup) on less than zero
//this is encouraged to use in wbcrypto instead of the internal macro
#define THROW_ONNEG(f)      \
    do                           \
    {                            \
        if( ( ret = (f) ) < 0 ) \
            goto cleanup;        \
    } while( 0 )

//throw with this code
#define THROW(code) { ret = (code); goto cleanup; }

#define MAPPED_THROW(code, mapper) \
	do {                           \
        int __retval = code;       \
		switch(__retval) mapper    \
	} while (0);                   \

#endif
