#ifndef WBCRYPTO_ADAPTIVE_ERROR_CODE_H_
#define WBCRYPTO_ADAPTIVE_ERROR_CODE_H_

#include "stdint.h"

// ensures the error code is 16 bit positive value on 16-bit machines
#define WBCRYPTO_ADAPT_ERROR(code) ((sizeof(int)==16)?((int16_t)(-(code))):(int32_t)(code))

#endif // !WBCRYPTO_ADAPTIVE_ERROR_CODE_H_
