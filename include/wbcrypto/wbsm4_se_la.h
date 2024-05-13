
#include "wbmatrix/WBMatrix.h"
#include "crypto/sm4.h"
typedef unsigned char  u8;
typedef unsigned int   u32;
static Aff8 A[2039], B[2039];

#define GET32(pc)  (\
((uint32_t)(pc)[0] << 24) ^\
((uint32_t)(pc)[1] << 16) ^\
((uint32_t)(pc)[2] <<  8) ^\
((uint32_t)(pc)[3]))

#define PUT32(st, ct)\
(ct)[0] = (uint8_t)((st) >> 24);\
(ct)[1] = (uint8_t)((st) >> 16);\
(ct)[2] = (uint8_t)((st) >>  8);\
(ct)[3] = (uint8_t)(st)

typedef struct wbcrypto_wbsm4se_la_context
{
	uint32_t MM[32][3][4][256];
	uint32_t CC[32][4][256];
	uint32_t DD[32][4][256];
	uint32_t SEE[4][4][256];
	uint32_t FEE[4][4][256];
}wbcrypto_wbsm4se_la_context;

void wbcrypto_wbsm4_se_la_gen(wbcrypto_wbsm4se_la_context *ctx, uint8_t *key);
void wbcrypto_wbsm4_se_la_encrypt(unsigned char IN[], unsigned char OUT[], wbcrypto_wbsm4se_la_context *ctx);
int wbcrypto_wbsm4_se_la_ecb_encrypt(wbcrypto_wbsm4se_la_context *ctx, const unsigned char *input, size_t ilen, unsigned char *output);
int wbcrypto_wbsm4_se_la_cbc_encrypt(wbcrypto_wbsm4se_la_context *ctx, unsigned char* iv, const unsigned char *input, size_t ilen, unsigned char *output);
int wbcrypto_wbsm4_se_la_gcm_encrypt_init(WBCRYPTO_GCM128_CONTEXT* gcm_ctx, wbcrypto_wbsm4se_la_context *ctx, unsigned char* iv, size_t ivlen, 
										unsigned char* aad, size_t aadlen);
int wbcrypto_wbsm4_se_la_gcm_encrypt(WBCRYPTO_GCM128_CONTEXT* gcm_ctx, const unsigned char *input, size_t ilen, 
										unsigned char *output);
int wbcrypto_wbsm4_se_la_ctr_encrypt(wbcrypto_wbsm4se_la_context *ctx, unsigned char* iv, unsigned char* ecount_buf, unsigned int* num, const unsigned char *input, size_t ilen, unsigned char *output);
void wbcrypto_wbsm4_se_la_free(wbcrypto_wbsm4se_la_context *ctx);