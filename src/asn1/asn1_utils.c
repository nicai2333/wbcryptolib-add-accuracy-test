#include <mbedtls/asn1write.h>
#include "wbcrypto/internal/asn1_utils.h"
#include "wbcrypto/internal/marco_utils.h"
#include "mbedtls/ecp.h"

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

// COPY PASTED FROM BIGNUM.C //

#define ciL    (sizeof(mbedtls_mpi_uint))         /* chars in limb  */

/* Get a specific byte, without range checks. */
#define GET_BYTE( X, i )                                \
    ( ( ( X )->p[( i ) / ciL] >> ( ( ( i ) % ciL ) * 8 ) ) & 0xff )
// COPY PASTED FROM BIGNUM.C

size_t wbcrypto_asn1_mpi_buflength(const mbedtls_mpi* X)
{
	int ret;
	size_t len = 0;

	// Write the MPI
	len = mbedtls_mpi_size(X);

	// DER format assumes 2s complement for numbers, so the leftmost bit
	// should be 0 for positive numbers and 1 for negative numbers.
	//
	// according to mpi internals, after clipping, the GET_BYTE here should be the leftmost byte written 
	size_t bytes_to_store = X->n * ciL;
	if (bytes_to_store > len) {
		bytes_to_store = len;
	}
	unsigned char leftmost = GET_BYTE(X, bytes_to_store - 1 );
	if (X->s == 1 && leftmost & 0x80) {
		len += 1;
	}

	len += wbcrypto_asn1_len_buflength(len);
	len += WBCRYPTO_ASN1_TAG_BUFLENGTH;

	ret = (int)len;

	return(ret);
}

size_t wbcrypto_asn1_oid_buflength(size_t oid_len) {
	return 
		WBCRYPTO_ASN1_TAG_BUFLENGTH
		+ wbcrypto_asn1_len_buflength(oid_len)
		+ oid_len;
}

size_t wbcrypto_asn1_len_buflength(size_t len)
{
	if (len < 0x80) 
	{
		return(1);
	}
	
	if (len <= 0xFF) 
	{
		return(2);
	}

	if (len <= 0xFFFF)
	{
		return(3);
	}

	if (len <= 0xFFFFFF)
	{
		return(4);
	}

#if SIZE_MAX > 0xFFFFFFFF
	if (len <= 0xFFFFFFFF)
#endif
	{
		return(5);
	}

#if SIZE_MAX > 0xFFFFFFFF
	return(MBEDTLS_ERR_ASN1_INVALID_LENGTH);
#endif
}

size_t wbcrypto_asn1_octet_string_buflength(size_t size) {
	return
		WBCRYPTO_ASN1_TAG_BUFLENGTH
		+ wbcrypto_asn1_len_buflength(size)
		+ size
		;
}

int wbcrypto_asn1_get_oid(uint8_t** p, uint8_t* end, wbcrypto_asn1_oid* oid) {
	int ret;

	//header
	THROW_ONNZ(mbedtls_asn1_get_tag(p, end, &oid->len, MBEDTLS_ASN1_OID));

	//buffer
	if ((size_t)(end - *p) < oid->len) {
		THROW(MBEDTLS_ERR_ASN1_OUT_OF_DATA);
	}
	oid->p = *p;
	*p += oid->len;

cleanup:
	return ret;
}

int wbcrypto_asn1_get_octetstring(uint8_t** p, uint8_t* end, wbcrypto_asn1_octetstring* octet_string) {
	int ret;

	//header
	THROW_ONNZ(mbedtls_asn1_get_tag(p, end, &octet_string->len, MBEDTLS_ASN1_OCTET_STRING));
	
	//buffer
	if ((size_t)(end - *p) < octet_string->len) {
		THROW(MBEDTLS_ERR_ASN1_OUT_OF_DATA);
	}
	octet_string->p = *p;
	*p += octet_string->len;

cleanup:
	return ret;
}

int wbcrypto_asn1_get_bitstring(uint8_t** p, uint8_t* end, struct mbedtls_asn1_bitstring* bit_string) {
	int ret;

	uint8_t* p_old = *p;
	size_t size = 0;
	THROW_ONNZ(mbedtls_asn1_get_tag(p, end, &size, MBEDTLS_ASN1_BIT_STRING));
	uint8_t* p_after_tag = *p;

	*p = p_old;
	THROW_ONNZ(mbedtls_asn1_get_bitstring(p, p_after_tag + size, bit_string));

	ret = 0;
cleanup:
	return ret;
}