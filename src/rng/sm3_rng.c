#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "rng/sm3_rng.h"


static const uint8_t num[4] = { 0, 1, 2, 3 };

typedef struct {
	sm3_context sm3_ctx[2];
} sm3_df_ctx;

int sm3_rng_alloc(void **ctx)
{
	sm3_rng *tmp;
	tmp = jent_zalloc(sizeof(sm3_rng));
    if (!tmp)
		return 1;
	*ctx = tmp;

	return 0;
}

void sm3_rng_dealloc(void *ctx)
{
	sm3_rng *tmp = (sm3_rng *)ctx;
   
    jent_zfree(ctx, sizeof(sm3_rng));
}

static void sm3_df_init(sm3_df_ctx *df_ctx)
{
	uint8_t counter[4] = {0, 0, 0, 1};
	uint8_t seedlen[4] = {0, 0, 440/256, 440%256};
	//counter和seedlen放入uint32_t，因为输入需要是uint8_t所以转换成uint8_t数组

	sm3_init(&df_ctx->sm3_ctx[0]);
    sm3_starts(&df_ctx->sm3_ctx[0]);
	sm3_update(&df_ctx->sm3_ctx[0], counter, 4);//计数器0x00000001
	sm3_update(&df_ctx->sm3_ctx[0], seedlen, 4);
	counter[3] = 2;
	sm3_init(&df_ctx->sm3_ctx[1]);
    sm3_starts(&df_ctx->sm3_ctx[1]);
	sm3_update(&df_ctx->sm3_ctx[1], counter, 4);//计数器0x0000002
	sm3_update(&df_ctx->sm3_ctx[1], seedlen, 4);
}

static void sm3_df_update(sm3_df_ctx *df_ctx, const uint8_t *data, size_t datalen)
{
	if (data && datalen) {
		sm3_update(&df_ctx->sm3_ctx[0], data, datalen);
		sm3_update(&df_ctx->sm3_ctx[1], data, datalen);
	}
}

static void sm3_df_final(sm3_df_ctx *df_ctx, uint8_t out[55])
{
	uint8_t buf[32];
	sm3_final(&df_ctx->sm3_ctx[0], out);
	sm3_final(&df_ctx->sm3_ctx[1], buf);
	memcpy(out + 32, buf, 55 - 32);
}

int sm3_rng_init(sm3_rng *rng, const uint8_t *nonce, size_t nonce_len,
	const uint8_t *label, size_t label_len)
{
	sm3_df_ctx df_ctx;
	uint8_t entropy[512];

	if (Get_entropy(entropy,512,MODE_SM3)) {
		printf("Get entropy error!!\n");
		return -1;
	}

	// V = sm3_df(entropy || nonce || label)
	sm3_df_init(&df_ctx);
	sm3_df_update(&df_ctx, entropy, sizeof(entropy));
	sm3_df_update(&df_ctx, nonce, nonce_len);
	sm3_df_update(&df_ctx, label, label_len);
	sm3_df_final(&df_ctx, rng->V);

	// C = sm3_df(0x00 || V)
	sm3_df_init(&df_ctx);
	sm3_df_update(&df_ctx, &num[0], 1);
	sm3_df_update(&df_ctx, rng->V, 55);
	sm3_df_final(&df_ctx, rng->C);

	// reseed_counter = 1, last_ressed_time = now()
	rng->reseed_counter = 1;
	rng->last_reseed_time = time(NULL);

    jent_memset_secure(&df_ctx, sizeof(sm3_df_ctx));
	jent_memset_secure(entropy, sizeof(entropy));
	return 0;
}

int sm3_rng_reseed(sm3_rng *rng, const uint8_t *addin, size_t addin_len)
{
	sm3_df_ctx df_ctx;
	uint8_t entropy[512];

	// get_entropy
	if (Get_entropy(entropy,512,MODE_SM3)) {
		printf("Get entropy error!!\n");
		return -1;
	}

	// V = sm3_df(0x01 || entropy || V || appin)
	sm3_df_init(&df_ctx);
	sm3_df_update(&df_ctx, &num[1], 1);
	sm3_df_update(&df_ctx, entropy, sizeof(entropy));
	sm3_df_update(&df_ctx, rng->V, 55);
	sm3_df_update(&df_ctx, addin, addin_len);
	sm3_df_final(&df_ctx, rng->V);

	// C = sm3_df(0x00 || V)
	sm3_df_init(&df_ctx);
	sm3_df_update(&df_ctx, &num[0], 1);
	sm3_df_update(&df_ctx, rng->V, 55);
	sm3_df_final(&df_ctx, rng->C);

	// reseed_counter = 1, last_ressed_time = now()
	rng->reseed_counter = 1;
	rng->last_reseed_time = time(NULL);

	jent_memset_secure(&df_ctx, sizeof(sm3_df_ctx));
	jent_memset_secure(entropy, sizeof(entropy));
	return 0;
}

static void be_add(uint8_t r[55], const uint8_t *a, size_t alen)
{
	int i, j, carry = 0;

	for (i = 54, j = (int)(alen - 1); j >= 0; i--, j--) {//从最低8位开始
		carry += r[i] + a[j];//用32位的int存放这轮的加法结果，加上上一轮的进位
		r[i] = carry & 0xff;//进位后剩下的部分
		carry >>= 8;//进位的部分
	}
	
	for (; i >= 0; i--) {
		carry += r[i];//进位加上剩下的高位的r
		r[i] = carry & 0xff;
		carry >>= 8;
	}
}

int sm3_rng_generate(sm3_rng *rng, const uint8_t *addin, size_t addin_len,
	uint8_t *out, size_t outlen)
{
	sm3_context sm3_ctx;
	uint8_t H[32];
	uint8_t counter[4];

	if (!outlen || outlen > 32) {
		printf("Outlen error!!\n");
		return -1;
	}
	//如果未重播种次数和时间间隔达到阈值，执行重播种
	if (rng->reseed_counter > SM3_RNG_MAX_RESEED_COUNTER
		|| ((time(NULL) - rng->last_reseed_time) > SM3_RNG_MAX_RESEED_SECONDS)) {
		if (sm3_rng_reseed(rng, addin, addin_len) != 1) {
			printf("RNG reseed error!!\n");
			return -1;
		}
		if (addin) {
			addin = NULL;
		}
	}

	if (addin && addin_len) {
		uint8_t W[32];

		// W = sm3(0x02 || V || addin)
		sm3_init(&sm3_ctx);
        sm3_starts(&sm3_ctx);
		sm3_update(&sm3_ctx, &num[2], 1);
		sm3_update(&sm3_ctx, rng->V, 55);
		sm3_update(&sm3_ctx, addin, addin_len);
		sm3_final(&sm3_ctx, W);

		// V = (V + W) mod 2^440
		be_add(rng->V, W, 32);

		jent_memset_secure(W, sizeof(W));
	}

	// output sm3(V)
	sm3_init(&sm3_ctx);
    sm3_starts(&sm3_ctx);
	sm3_update(&sm3_ctx, rng->V, 55);
	if (outlen < 32) {
		uint8_t buf[32];
		sm3_final(&sm3_ctx, buf);
		memcpy(out, buf, outlen);
	} else {
		sm3_final(&sm3_ctx, out);
	}

	// H = sm3(0x03 || V)
	sm3_init(&sm3_ctx);
    sm3_starts(&sm3_ctx);
	sm3_update(&sm3_ctx, &num[3], 1);
	sm3_update(&sm3_ctx, rng->V, 55);
	sm3_final(&sm3_ctx, H);

	// V = (V + H + C + reseed_counter) mod 2^440
	be_add(rng->V, H, 32);
	be_add(rng->V, rng->C, 55);
	counter[0] = (rng->reseed_counter >> 24) & 0xff;
	counter[1] = (rng->reseed_counter >> 16) & 0xff;
	counter[2] = (rng->reseed_counter >>  8) & 0xff;
	counter[3] = (rng->reseed_counter      ) & 0xff;
	be_add(rng->V, counter, 4);

	(rng->reseed_counter)++;

	jent_memset_secure(&sm3_ctx, sizeof(sm3_context));
	jent_memset_secure(H, sizeof(H));
	return 0;
}
