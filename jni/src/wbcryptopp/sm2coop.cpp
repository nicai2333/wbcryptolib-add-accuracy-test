#include "wbcryptopp/sm2coop.h"
#include "memory_view/buffer_view.h"
#include <mbedtls/ecp_internal.h>


void wbcrypto::sm2coop_decrypt_client_read_binary(wbcrypto_sm2coop_decrypt_client_session* ctx, const array_view<uint8_t>& buffer, const mbedtls_ecp_group* grp) {
	//HACK: because Z=0 will let the function below think C1 have only length of 1
	mbedtls::mpi_read_value(&ctx->c1point.Z, 1);
	auto c1_size = mbedtls::ecp_point_write_binary_size(&ctx->c1point, grp);
	auto expected_size = c1_size
		+ sizeof(ctx->c2_len)
		+ sizeof(ctx->c2_offset)
		+ sizeof(ctx->c3_len)
		+ sizeof(ctx->c3_offset);

	if(buffer.size() < expected_size) {
		throw wbcrypto::sm2coop_exception(WBCRYPTO_ERR_SM2COOP_BAD_INPUT_DATA);
	}

	mbedtls::ecp_point_read_binary(&ctx->c1point, buffer.subrange(0,c1_size), grp);
	auto data_ptr = (uint64_t*)(buffer.data() + c1_size);
	ctx->c2_len = *(data_ptr++);
	ctx->c2_offset = *(data_ptr++);
	ctx->c3_len = *(data_ptr++);
	ctx->c3_offset = *(data_ptr++);
}

size_t wbcrypto::sm2coop_decrypt_client_write_binary_size(const wbcrypto_sm2coop_decrypt_client_session* ctx, const mbedtls_ecp_group* grp) {
	return mbedtls::ecp_point_write_binary_size(&ctx->c1point, grp)
		+ sizeof(ctx->c2_len)
		+ sizeof(ctx->c2_offset)
		+ sizeof(ctx->c3_len)
		+ sizeof(ctx->c3_offset)
		;
}

void wbcrypto::sm2coop_decrypt_client_write_binary(const wbcrypto_sm2coop_decrypt_client_session* ctx, buffer_view<uint8_t>& buffer, const mbedtls_ecp_group* grp) {
	if(buffer.writable_size() < sm2coop_decrypt_client_write_binary_size(ctx, grp)){
		throw wbcrypto::sm2coop_exception(WBCRYPTO_ERR_SM2COOP_OUTPUT_TOO_LARGE);
	}
	
	mbedtls::ecp_point_write_binary(&ctx->c1point, buffer, grp);
	
	auto data_ptr = (uint64_t*)(buffer.writable_data());
	*(data_ptr++) = ctx->c2_len;
	*(data_ptr++) = ctx->c2_offset;
	*(data_ptr++) = ctx->c3_len;
	*(data_ptr++) = ctx->c3_offset;
	buffer.advance((uint8_t*)data_ptr - buffer.writable_data());
}