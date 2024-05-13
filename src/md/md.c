#include "crypto/md.h"
#include "mbedtls/md_internal.h"
#include "crypto/sm3.h"
#include <memory.h>
#include <stdlib.h>

#define ALLOC( type )                                                   \
    do {                                                                \
        ctx->md_ctx = calloc( 1, sizeof( wbcrypto_##type##_context ) ); \
        if( ctx->md_ctx == NULL )                                       \
            return( MBEDTLS_ERR_MD_ALLOC_FAILED );                      \
        wbcrypto_##type##_init( ctx->md_ctx );                           \
    }                                                                   \
    while( 0 )

int wbcrypto_md_setup(mbedtls_md_context_t* ctx, const mbedtls_md_info_t* md_info, int hmac)
{
	if (md_info == NULL || ctx == NULL)
		return(MBEDTLS_ERR_MD_BAD_INPUT_DATA);

	switch (md_info->type)
	{
		case WBCRYPTO_MD_SM3:
			ALLOC(sm3);
			break;
		default:
			return(MBEDTLS_ERR_MD_BAD_INPUT_DATA);
	}

	if (hmac != 0)
	{
		ctx->hmac_ctx = calloc(2, md_info->block_size);
		if (ctx->hmac_ctx == NULL)
		{
			mbedtls_md_free(ctx);
			return(MBEDTLS_ERR_MD_ALLOC_FAILED);
		}
	}

	ctx->md_info = md_info;

	return(0);
}
#undef ALLOC

int wbcrypto_md_starts(mbedtls_md_context_t* ctx)
{
	if (ctx == NULL || ctx->md_info == NULL)
		return(MBEDTLS_ERR_MD_BAD_INPUT_DATA);

	switch (ctx->md_info->type)
	{
		case WBCRYPTO_MD_SM3:
			return(wbcrypto_sm3_starts(ctx->md_ctx));
		default:
			return(MBEDTLS_ERR_MD_BAD_INPUT_DATA);
	}
}

int wbcrypto_md_update(mbedtls_md_context_t* ctx, const unsigned char* input, size_t ilen)
{
	if (ctx == NULL || ctx->md_info == NULL)
		return(MBEDTLS_ERR_MD_BAD_INPUT_DATA);

	switch (ctx->md_info->type)
	{
		case WBCRYPTO_MD_SM3:
			return(wbcrypto_sm3_update(ctx->md_ctx, input, ilen));
		default:
			return(MBEDTLS_ERR_MD_BAD_INPUT_DATA);
	}
}

int wbcrypto_md_finish(mbedtls_md_context_t* ctx, unsigned char* output)
{
	if (ctx == NULL || ctx->md_info == NULL)
		return(MBEDTLS_ERR_MD_BAD_INPUT_DATA);

	switch (ctx->md_info->type)
	{
		case WBCRYPTO_MD_SM3:
			return(wbcrypto_sm3_finish(ctx->md_ctx, output));
		default:
			return(MBEDTLS_ERR_MD_BAD_INPUT_DATA);
	}
}

int wbcrypto_md_hmac_starts(mbedtls_md_context_t* ctx, const unsigned char* key, size_t keylen)
{
	int ret;
	unsigned char sum[MBEDTLS_MD_MAX_SIZE];
	unsigned char* ipad, * opad;
	size_t i;

	if (ctx == NULL || ctx->md_info == NULL || ctx->hmac_ctx == NULL)
		return(MBEDTLS_ERR_MD_BAD_INPUT_DATA);

	if (keylen > (size_t)ctx->md_info->block_size)
	{
		if ((ret = wbcrypto_md_starts(ctx)) != 0)
			goto cleanup;
		if ((ret = wbcrypto_md_update(ctx, key, keylen)) != 0)
			goto cleanup;
		if ((ret = wbcrypto_md_finish(ctx, sum)) != 0)
			goto cleanup;

		keylen = ctx->md_info->size;
		key = sum;
	}

	ipad = (unsigned char*)ctx->hmac_ctx;
	opad = (unsigned char*)ctx->hmac_ctx + ctx->md_info->block_size;

	memset(ipad, 0x36, ctx->md_info->block_size);
	memset(opad, 0x5C, ctx->md_info->block_size);

	for (i = 0; i < keylen; i++)
	{
		ipad[i] = (unsigned char)(ipad[i] ^ key[i]);
		opad[i] = (unsigned char)(opad[i] ^ key[i]);
	}

	if ((ret = wbcrypto_md_starts(ctx)) != 0)
		goto cleanup;
	if ((ret = wbcrypto_md_update(ctx, ipad,
		ctx->md_info->block_size)) != 0)
		goto cleanup;

cleanup:
	//FIXME: we dont want to deal with this zeroize security now
	//mbedtls_platform_zeroize(sum, sizeof(sum));
	return(ret);
}

int wbcrypto_md_hmac_update(mbedtls_md_context_t* ctx, const unsigned char* input, size_t ilen)
{
	if (ctx == NULL || ctx->md_info == NULL || ctx->hmac_ctx == NULL)
		return(MBEDTLS_ERR_MD_BAD_INPUT_DATA);

	return(wbcrypto_md_update(ctx, input, ilen));
}

int wbcrypto_md_hmac_finish(mbedtls_md_context_t* ctx, unsigned char* output)
{
	int ret;
	unsigned char tmp[MBEDTLS_MD_MAX_SIZE];
	unsigned char* opad;

	if (ctx == NULL || ctx->md_info == NULL || ctx->hmac_ctx == NULL)
		return(MBEDTLS_ERR_MD_BAD_INPUT_DATA);

	opad = (unsigned char*)ctx->hmac_ctx + ctx->md_info->block_size;

	if ((ret = wbcrypto_md_finish(ctx, tmp)) != 0)
		return(ret);
	if ((ret = wbcrypto_md_starts(ctx)) != 0)
		return(ret);
	if ((ret = wbcrypto_md_update(ctx, opad, ctx->md_info->block_size)) != 0)
		return(ret);
	if ((ret = wbcrypto_md_update(ctx, tmp, ctx->md_info->size)) != 0)
		return(ret);
	return(wbcrypto_md_finish(ctx, output));
}

int wbcrypto_md_hmac(
	const mbedtls_md_info_t* md_info,
	const unsigned char* key, size_t keylen,
	const unsigned char* input, size_t ilen,
	unsigned char* output
) {
	mbedtls_md_context_t ctx;
	int ret;

	if (md_info == NULL)
		return(MBEDTLS_ERR_MD_BAD_INPUT_DATA);

	mbedtls_md_init(&ctx);

	if ((ret = wbcrypto_md_setup(&ctx, md_info, 1)) != 0)
		goto cleanup;

	if ((ret = wbcrypto_md_hmac_starts(&ctx, key, keylen)) != 0)
		goto cleanup;
	if ((ret = wbcrypto_md_hmac_update(&ctx, input, ilen)) != 0)
		goto cleanup;
	if ((ret = wbcrypto_md_hmac_finish(&ctx, output)) != 0)
		goto cleanup;

cleanup:
	mbedtls_md_free(&ctx);
	return(ret);
}

const mbedtls_md_info_t wbcrypto_sm3_md_info = {
	"SM3",
	((mbedtls_md_type_t)WBCRYPTO_MD_SM3),
	32,
	64
};