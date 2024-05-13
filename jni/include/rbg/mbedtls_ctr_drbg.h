#ifndef WBCRYPTO_JNI_RBG_MBEDTLS_CTR_DRBG_H_
#define WBCRYPTO_JNI_RBG_MBEDTLS_CTR_DRBG_H_

#include "rbg.h"
#include <mbedtlspp/ctr_drbg.h>

/**
* implementation using mbedtls's ctr_drbg
*/
class mbedtls_ctr_drbg : public rbg {

	public:

	static mbedtls_ctr_drbg with_platform_default(const array_view<uint8_t>& seed = array_view<uint8_t>{}) {
		mbedtls_ctr_drbg drbg;
		drbg.entropy = mbedtls::entropy_context::with_platform_entropy_source();
		drbg.ctr_drbg = mbedtls::ctr_drbg_context::with_entropy_source(drbg.entropy, seed);
		return std::move(drbg);
	}

	static mbedtls_ctr_drbg with_null_entropy(const array_view<uint8_t>& seed = array_view<uint8_t>{}) {
		mbedtls_ctr_drbg drbg;
		drbg.ctr_drbg = mbedtls::ctr_drbg_context::with_entropy_source(drbg.entropy, seed);
		return std::move(drbg);
	}

	static mbedtls_ctr_drbg with_entropy(mbedtls::entropy_context ent, const array_view<uint8_t>& seed = array_view<uint8_t>{}) {
		mbedtls_ctr_drbg drbg;
		drbg.entropy = std::move(ent);
		drbg.ctr_drbg = mbedtls::ctr_drbg_context::with_entropy_source(drbg.entropy, seed);
		return std::move(drbg);
	}

	mbedtls_ctr_drbg() = default;
	mbedtls_ctr_drbg(mbedtls_ctr_drbg&& other) = default;
	mbedtls_ctr_drbg& operator=(mbedtls_ctr_drbg&& other) = default;
	virtual ~mbedtls_ctr_drbg() = default;


	virtual int random(unsigned char* output, size_t output_len) {
		return mbedtls_ctr_drbg_random(ctr_drbg.ptr(), output, output_len);
	}

	private:

	mbedtls::entropy_context entropy;
	mbedtls::ctr_drbg_context ctr_drbg;

};

#endif