#ifndef WBCRYPTO_TEST_ASSERTS_H_
#define WBCRYPTO_TEST_ASSERTS_H_

#include "wbcrypto/internal/marco_utils.h"

#define ASSERT_SUCCESS(func) THROW_ONNZ(func)
#define ASSERT_SUCCESS_NONNEG(func) THROW_ONNEG(func)
#define ASSERT_ERROR_CODE(func, code) if((func)==code) { ret = 0; } else { ret = -1; goto cleanup; }
#define ASSERT_ERROR(func) if((func)!=0) { ret = 0; } else { ret = -1; goto cleanup; }

//asks the compiler pardon the unused cleanup
#define USE_CLEANUP { goto cleanup; }

//asks the compiler pardon the unused variable
#define USE_VAR(var) ((void)var)
#endif
