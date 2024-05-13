/**
 * \file asn1_utils.h
 *
 * \brief ASN.1 writing utils, such as expected space consumption when writing using asn1write.h functions
 */
#ifndef WBCRYPTO_INTERNAL_ASN1_UTIL_H
#define WBCRYPTO_INTERNAL_ASN1_UTIL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WBCRYPTO_THROW_ON_NEG(f)       \
    do                           \
    {                            \
        if( ( ret = (f) ) < 0 ) \
            goto cleanup;        \
    } while( 0 )


	#define WBCRYPTO_ASN1_TAG_BUFLENGTH 1

	//the buf size consumed with this oid
	size_t wbcrypto_asn1_oid_buflength(size_t oid_len);

	//the buf size consumed with this mpi
	size_t wbcrypto_asn1_mpi_buflength(const mbedtls_mpi* X);

	//the buf size consumed with length of this value
	size_t wbcrypto_asn1_len_buflength(size_t len);

	//the buf size consumed with length of this octet string
	size_t wbcrypto_asn1_octet_string_buflength(size_t data_size);

	
	typedef struct {
		size_t len;                 /**< ASN1 length, in octets. */
		unsigned char* p;           /**< Raw ASN1 data for the OID */
	} wbcrypto_asn1_oid;

	/**
	 * \brief       Retrieve an OID ASN.1 tag and its value.
	 *              Updates the pointer to immediately behind the full tag.
	 *
	 * \return      0 on successful,
	 *                  family under MBEDTLS_ERR_ASN1 on error
	 *
	 */
	int wbcrypto_asn1_get_oid(uint8_t** p, uint8_t* end, wbcrypto_asn1_oid* oid);
	
	typedef struct {
		size_t len;                 /**< ASN1 length, in octets. */
		unsigned char* p;           /**< Raw ASN1 data for the octet string */
	} wbcrypto_asn1_octetstring;

    /**
	 * \brief       Retrieve an octet string ASN.1 tag and its value.
	 *              Updates the pointer to immediately behind the full tag.
	 *              
	 * \return      0 on successful,
	 *                  family under MBEDTLS_ERR_ASN1 on error
	 *
	 */
	int wbcrypto_asn1_get_octetstring(uint8_t** p, uint8_t* end, wbcrypto_asn1_octetstring* octet_string);

	/**
	 * \brief       Retrieve an bitstring ASN.1 tag and its value.
	 *              Updates the pointer to immediately behind the full tag.
	 *
	 * \note        this is a wrapper to mbedtls's version so that it does not assume end to be the end of the string¡®
	 *
	 * \return      0 on successful,
	 *                  family under MBEDTLS_ERR_ASN1 on error
	 *
	 */
	int wbcrypto_asn1_get_bitstring(uint8_t** p, uint8_t* end, struct mbedtls_asn1_bitstring* bit_string);

#ifdef __cplusplus
}
#endif

#endif /* asn1_utils.h */
