/*
This file is a copy & paste adoption of MBEDTLS
to support SM2 curve
*/

#include <mbedtls/ecp.h>
#include <mbedtls/bignum.h>

#include <string.h>

#if (defined(__ARMCC_VERSION) || defined(_MSC_VER) ) && \
    !defined(inline) && !defined(__cplusplus)
#define inline __inline
#endif

/*
 * Conversion macros for embedded constants:
 * build lists of mbedtls_mpi_uint's from lists of unsigned char's grouped by 8, 4 or 2
 */
#if defined(MBEDTLS_HAVE_INT32)

#define BYTES_TO_T_UINT_4(a, b, c, d)             \
    ( (mbedtls_mpi_uint) a <<  0 ) |                          \
    ( (mbedtls_mpi_uint) b <<  8 ) |                          \
    ( (mbedtls_mpi_uint) c << 16 ) |                          \
    ( (mbedtls_mpi_uint) d << 24 )

#define BYTES_TO_T_UINT_2(a, b)                   \
    BYTES_TO_T_UINT_4( a, b, 0, 0 )

#define BYTES_TO_T_UINT_8(a, b, c, d, e, f, g, h) \
    BYTES_TO_T_UINT_4( a, b, c, d ),                \
    BYTES_TO_T_UINT_4( e, f, g, h )

#else /* 64-bits */

#define BYTES_TO_T_UINT_8( a, b, c, d, e, f, g, h ) \
    ( (mbedtls_mpi_uint) a <<  0 ) |                          \
    ( (mbedtls_mpi_uint) b <<  8 ) |                          \
    ( (mbedtls_mpi_uint) c << 16 ) |                          \
    ( (mbedtls_mpi_uint) d << 24 ) |                          \
    ( (mbedtls_mpi_uint) e << 32 ) |                          \
    ( (mbedtls_mpi_uint) f << 40 ) |                          \
    ( (mbedtls_mpi_uint) g << 48 ) |                          \
    ( (mbedtls_mpi_uint) h << 56 )

#define BYTES_TO_T_UINT_4( a, b, c, d )             \
    BYTES_TO_T_UINT_8( a, b, c, d, 0, 0, 0, 0 )

#define BYTES_TO_T_UINT_2( a, b )                   \
    BYTES_TO_T_UINT_8( a, b, 0, 0, 0, 0, 0, 0 )

#endif /* bits in mbedtls_mpi_uint */

 /*
 * Note: the constants are in little-endian order
 * to be directly usable in MPIs
 */

 /* sm2 */

static const mbedtls_mpi_uint sm2_256v1_p[] = {
        BYTES_TO_T_UINT_8(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF),
        BYTES_TO_T_UINT_8(0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF),
        BYTES_TO_T_UINT_8(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF),
        BYTES_TO_T_UINT_8(0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF),

};

/* a */
static const mbedtls_mpi_uint sm2_256v1_a[] = {
        BYTES_TO_T_UINT_8(0xFC, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF),
        BYTES_TO_T_UINT_8(0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF),
        BYTES_TO_T_UINT_8(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF),
        BYTES_TO_T_UINT_8(0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF),
};

/* b */
static const mbedtls_mpi_uint sm2_256v1_b[] = {
        BYTES_TO_T_UINT_8(0x93, 0x0E, 0x94, 0x4D, 0x41, 0xBD, 0xBC, 0xDD),
        BYTES_TO_T_UINT_8(0x92, 0x8F, 0xAB, 0x15, 0xF5, 0x89, 0x97, 0xF3),
        BYTES_TO_T_UINT_8(0xA7, 0x09, 0x65, 0xCF, 0x4B, 0x9E, 0x5A, 0x4D),
        BYTES_TO_T_UINT_8(0x34, 0x5E, 0x9F, 0x9D, 0x9E, 0xFA, 0xE9, 0x28),
};
/* x */
static const mbedtls_mpi_uint sm2_256v1_gx[] = {
        BYTES_TO_T_UINT_8(0xC7, 0x74, 0x4C, 0x33, 0x89, 0x45, 0x5A, 0x71),
        BYTES_TO_T_UINT_8(0xE1, 0x0B, 0x66, 0xF2, 0xBF, 0x0B, 0xE3, 0x8F),
        BYTES_TO_T_UINT_8(0x94, 0xC9, 0x39, 0x6A, 0x46, 0x04, 0x99, 0x5F),
        BYTES_TO_T_UINT_8(0x19, 0x81, 0x19, 0x1F, 0x2C, 0xAE, 0xC4, 0x32),
};
/* y */
static const mbedtls_mpi_uint sm2_256v1_gy[] = {
        BYTES_TO_T_UINT_8(0xA0, 0xF0, 0x39, 0x21, 0xE5, 0x32, 0xDF, 0x02),
        BYTES_TO_T_UINT_8(0x40, 0x47, 0x2A, 0xC6, 0x7C, 0x87, 0xA9, 0xD0),
        BYTES_TO_T_UINT_8(0x53, 0x21, 0x69, 0x6B, 0xE3, 0xCE, 0xBD, 0x59),
        BYTES_TO_T_UINT_8(0x9C, 0x77, 0xF6, 0xF4, 0xA2, 0x36, 0x37, 0xBC),
};
/* n */
static const mbedtls_mpi_uint sm2_256v1_n[] = {
        BYTES_TO_T_UINT_8(0x23, 0x41, 0xD5, 0x39, 0x09, 0xF4, 0xBB, 0x53),
        BYTES_TO_T_UINT_8(0x2B, 0x05, 0xC6, 0x21, 0x6B, 0xDF, 0x03, 0x72),
        BYTES_TO_T_UINT_8(0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF),
        BYTES_TO_T_UINT_8(0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF),
};

/*
 * Create an MPI from embedded constants
 * (assumes len is an exact multiple of sizeof mbedtls_mpi_uint)
 */
static inline void ecp_mpi_load(mbedtls_mpi* X, const mbedtls_mpi_uint* p, size_t len) {
    X->s = 1;
    X->n = len / sizeof(mbedtls_mpi_uint);
    X->p = (mbedtls_mpi_uint*)p;
}

/*
 * Set an MPI to static value 1
 */
static inline void ecp_mpi_set1(mbedtls_mpi* X) {
    static mbedtls_mpi_uint one[] = { 1 };
    X->s = 1;
    X->n = 1;
    X->p = one;
}

/*
 * Make group available from embedded constants
 */
static int ecp_group_load(mbedtls_ecp_group* grp,
    const mbedtls_mpi_uint* p, size_t plen,
    const mbedtls_mpi_uint* a, size_t alen,
    const mbedtls_mpi_uint* b, size_t blen,
    const mbedtls_mpi_uint* gx, size_t gxlen,
    const mbedtls_mpi_uint* gy, size_t gylen,
    const mbedtls_mpi_uint* n, size_t nlen
) {
    ecp_mpi_load(&grp->P, p, plen);
    if (a != NULL)
        ecp_mpi_load(&grp->A, a, alen);
    ecp_mpi_load(&grp->B, b, blen);
    ecp_mpi_load(&grp->N, n, nlen);

    ecp_mpi_load(&grp->G.X, gx, gxlen);
    ecp_mpi_load(&grp->G.Y, gy, gylen);
    ecp_mpi_set1(&grp->G.Z);

    grp->pbits = mbedtls_mpi_bitlen(&grp->P);
    grp->nbits = mbedtls_mpi_bitlen(&grp->N);

    grp->h = 1;

    return (0);
}

#define LOAD_GROUP_A(G)   ecp_group_load( grp,            \
                            G ## _p,  sizeof( G ## _p  ),   \
                            G ## _a,  sizeof( G ## _a  ),   \
                            G ## _b,  sizeof( G ## _b  ),   \
                            G ## _gx, sizeof( G ## _gx ),   \
                            G ## _gy, sizeof( G ## _gy ),   \
                            G ## _n,  sizeof( G ## _n  ) )

#define LOAD_GROUP(G)     ecp_group_load( grp,            \
                            G ## _p,  sizeof( G ## _p  ),   \
                            NULL,     0,                    \
                            G ## _b,  sizeof( G ## _b  ),   \
                            G ## _gx, sizeof( G ## _gx ),   \
                            G ## _gy, sizeof( G ## _gy ),   \
                            G ## _n,  sizeof( G ## _n  ) )

/*
 * For these primes, we need to handle data in chunks of 32 bits.
 * This makes it more complicated if we use 64 bits limbs in MPI,
 * which prevents us from using a uniform access method as for p192.
 *
 * So, we define a mini abstraction layer to access 32 bit chunks,
 * load them in 'cur' for work, and store them back from 'cur' when done.
 *
 * While at it, also define the size of N in terms of 32-bit chunks.
 */
#define LOAD32 cur = A(i);

#if defined(MBEDTLS_HAVE_INT32) /* 32 bit */

#define MAX32 N->n
#define A(j) N->p[j]
#define STORE32 N->p[i] = cur;

#else /* 64-bit */

#define MAX32 N->n * 2
#define A(j) j % 2 ? (uint32_t)(N->p[j / 2] >> 32) : (uint32_t)(N->p[j / 2])
#define STORE32                                       \
    if (i % 2)                                        \
    {                                                 \
        N->p[i / 2] &= 0x00000000FFFFFFFF;            \
        N->p[i / 2] |= ((mbedtls_mpi_uint)cur) << 32; \
    }                                                 \
    else                                              \
    {                                                 \
        N->p[i / 2] &= 0xFFFFFFFF00000000;            \
        N->p[i / 2] |= (mbedtls_mpi_uint)cur;         \
    }

#endif /* sizeof( mbedtls_mpi_uint ) */

 /*
  * Helpers for addition and subtraction of chunks, with signed carry.
  */
static inline void add32(uint32_t* dst, uint32_t src, signed char* carry)
{
    *dst += src;
    *carry += (*dst < src);
}

static inline void sub32(uint32_t* dst, uint32_t src, signed char* carry)
{
    *carry -= (*dst < src);
    *dst -= src;
}

#define ADD(j) add32(&cur, A(j), &c);
#define SUB(j) sub32(&cur, A(j), &c);

/*
 * Helpers for the main 'loop'
 * (see fix_negative for the motivation of C)
 */
#define INIT(b)                                                                 \
    int ret;                                                                    \
    signed char c = 0, cc;                                                      \
    uint32_t cur;                                                               \
    size_t i = 0, bits = b;                                                     \
    mbedtls_mpi C;                                                              \
    mbedtls_mpi_uint Cp[b / 8 / sizeof(mbedtls_mpi_uint) + 1];                  \
                                                                                \
    C.s = 1;                                                                    \
    C.n = b / 8 / sizeof(mbedtls_mpi_uint) + 1;                                 \
    C.p = Cp;                                                                   \
    memset(Cp, 0, C.n * sizeof(mbedtls_mpi_uint));                              \
                                                                                \
    MBEDTLS_MPI_CHK(mbedtls_mpi_grow(N, b * 2 / 8 / sizeof(mbedtls_mpi_uint))); \
    LOAD32;

#define NEXT                  \
    STORE32;                  \
    i++;                      \
    LOAD32;                   \
    cc = c;                   \
    c = 0;                    \
    if (cc < 0)               \
        sub32(&cur, -cc, &c); \
    else                      \
        add32(&cur, cc, &c);

#define LAST             \
    STORE32;             \
    i++;                 \
    cur = c > 0 ? c : 0; \
    STORE32;             \
    cur = 0;             \
    while (++i < MAX32)  \
    {                    \
        STORE32;         \
    }                    \
    if (c < 0)           \
        fix_negative(N, c, &C, bits);

 /*
  * If the result is negative, we get it in the form
  * c * 2^(bits + 32) + N, with c negative and N positive shorter than 'bits'
  */
static inline int fix_negative(mbedtls_mpi* N, signed char c, mbedtls_mpi* C, size_t bits)
{
    int ret;

    /* C = - c * 2^(bits + 32) */
#if !defined(MBEDTLS_HAVE_INT64)
    ((void)bits);
#else
    if (bits == 224)
        C->p[C->n - 1] = ((mbedtls_mpi_uint)-c) << 32;
    else
#endif
        C->p[C->n - 1] = (mbedtls_mpi_uint)-c;

    /* N = - ( C - N ) */
    MBEDTLS_MPI_CHK(mbedtls_mpi_sub_abs(N, C, N));
    N->s = -1;

cleanup:

    return (ret);
}


static int ecp_mod_sm2_p256v1(mbedtls_mpi* N)
{
    INIT(256);

    ADD(8);
    ADD(9);
    ADD(10);
    ADD(11);
    ADD(12);
    ADD(13);
    ADD(13);
    ADD(14);
    ADD(14);
    ADD(15);
    ADD(15);
    NEXT; // A0

    ADD(9);
    ADD(10);
    ADD(11);
    ADD(12);
    ADD(13);
    ADD(14);
    ADD(14);
    ADD(15);
    ADD(15);
    NEXT; // A1

    SUB(8);
    SUB(9);
    SUB(13);
    SUB(14);
    NEXT; // A2

    ADD(8);
    ADD(11);
    ADD(12);
    ADD(13);
    ADD(13);
    ADD(14);
    ADD(15);
    NEXT; // A3

    ADD(9);
    ADD(12);
    ADD(13);
    ADD(14);
    ADD(14);
    ADD(15);
    NEXT; // A4

    ADD(10);
    ADD(13);
    ADD(14);
    ADD(15);
    ADD(15);
    NEXT; // A5

    ADD(11);
    ADD(14);
    ADD(15);
    NEXT; // A6

    ADD(8);
    ADD(9);
    ADD(10);
    ADD(11);
    ADD(12);
    ADD(12);
    ADD(13);
    ADD(13);
    ADD(14);
    ADD(14);
    ADD(15);
    ADD(15);
    ADD(15);
    LAST; // A7

cleanup:
    return (ret);
}

int wbcrypto_sm2_load_default_group(mbedtls_ecp_group* grp) {
	if(grp==NULL) {
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
	}
	mbedtls_ecp_group_free(grp);
	mbedtls_ecp_group_init(grp);
	grp->id = MBEDTLS_ECP_DP_NONE;
    grp->modp = ecp_mod_sm2_p256v1;
	return LOAD_GROUP_A(sm2_256v1);
}
