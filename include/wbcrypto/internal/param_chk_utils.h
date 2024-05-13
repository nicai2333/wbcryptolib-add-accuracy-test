/**
 * Parameter Check Utility for internal usage
 *
 * this is a copy from mbedtls's platform_utils, but the failed function is not used for now
 */
#ifndef WBCRYPTO_INTERNAL_PARAM_CHK_UTILS_H
#define WBCRYPTO_INTERNAL_PARAM_CHK_UTILS_H

#define WBCRYPTO_CHECK_PARAMS

#if defined(WBCRYPTO_CHECK_PARAMS)

#if defined(WBCRYPTO_CHECK_PARAMS_ASSERT)
/* Allow the user to define WBCRYPTO_PARAM_FAILED to something like assert
 * (which is what our config.h suggests). */
#include <assert.h>
#endif /* WBCRYPTO_CHECK_PARAMS_ASSERT */

#if defined(WBCRYPTO_PARAM_FAILED)
 /** An alternative definition of WBCRYPTO_PARAM_FAILED has been set in config.h.
  *
  * This flag can be used to check whether it is safe to assume that
  * WBCRYPTO_PARAM_FAILED() will expand to a call to WBCRYPTO_param_failed().
  */
#define WBCRYPTO_PARAM_FAILED_ALT

#elif defined(WBCRYPTO_CHECK_PARAMS_ASSERT)
#define WBCRYPTO_PARAM_FAILED( cond ) assert( cond )
#define WBCRYPTO_PARAM_FAILED_ALT

#else /* WBCRYPTO_PARAM_FAILED */
#define WBCRYPTO_PARAM_FAILED( cond ) \
    wbcrypto_param_failed( #cond, __FILE__, __LINE__ )

 /**
  * \brief       User supplied callback function for parameter validation failure.
  *              See #WBCRYPTO_CHECK_PARAMS for context.
  *
  *              This function will be called unless an alternative treatement
  *              is defined through the #WBCRYPTO_PARAM_FAILED macro.
  *
  *              This function can return, and the operation will be aborted, or
  *              alternatively, through use of setjmp()/longjmp() can resume
  *              execution in the application code.
  *
  * \param failure_condition The assertion that didn't hold.
  * \param file  The file where the assertion failed.
  * \param line  The line in the file where the assertion failed.
  */
void wbcrypto_param_failed(const char* failure_condition, const char* file, int line);
#endif /* WBCRYPTO_PARAM_FAILED */

/* Internal macro meant to be called only from within the library. */
#define WBCRYPTO_INTERNAL_VALIDATE_RET( cond, ret )  \
    do {                                            \
        if( !(cond) )                               \
        {                                           \
            /*WBCRYPTO_PARAM_FAILED( cond );*/           \
            return( ret );                          \
        }                                           \
    } while( 0 )

/* Internal macro meant to be called only from within the library. */
#define WBCRYPTO_INTERNAL_VALIDATE( cond )           \
    do {                                            \
        if( !(cond) )                               \
        {                                           \
            /*WBCRYPTO_PARAM_FAILED( cond );*/           \
            return;                                 \
        }                                           \
    } while( 0 )

#else /* WBCRYPTO_CHECK_PARAMS */

/* Internal macros meant to be called only from within the library. */
#define WBCRYPTO_INTERNAL_VALIDATE_RET( cond, ret )  do { } while( 0 )
#define WBCRYPTO_INTERNAL_VALIDATE( cond )           do { } while( 0 )

#endif /* WBCRYPTO_CHECK_PARAMS */

#endif