/*
 * @Author:
 * @Date: 2023/5/28 13:19
 * @Description:
 */

#include "modes_lcl.h"
#include <string.h>

#ifndef MODES_DEBUG
# ifndef NDEBUG
#  define NDEBUG
# endif
#endif
#include <assert.h>

/* NOTE: the IV/counter CTR mode is big-endian.  The code itself
 * is endian-neutral. */

/* increment counter (128-bit int) by 1 */
static void ctr128_inc(unsigned char *counter) {
    u32 n=16;
    u8  c;

    do {
        --n;
        c = counter[n];
        ++c;
        counter[n] = c;
        if (c) return;
    } while (n);
}

#if !defined(OPENSSL_SMALL_FOOTPRINT)
static void ctr128_inc_aligned(unsigned char *counter) {
    size_t *data,c,n;
    const union { long one; char little; } is_endian = {1};

    if (is_endian.little) {
        ctr128_inc(counter);
        return;
    }

    data = (size_t *)counter;
    n = 16/sizeof(size_t);
    do {
        --n;
        c = data[n];
        ++c;
        data[n] = c;
        if (c) return;
    } while (n);
}
#endif

/* The input encrypted as though 128bit counter mode is being
 * used.  The extra state information to record how much of the
 * 128bit block we have used is contained in *num, and the
 * encrypted counter is kept in ecount_buf.  Both *num and
 * ecount_buf must be initialised with zeros before the first
 * call to CRYPTO_ctr128_encrypt().
 *
 * This algorithm assumes that the counter is in the x lower bits
 * of the IV (ivec), and that the application has full control over
 * overflow and the rest of the IV.  This implementation takes NO
 * responsability for checking that the counter doesn't overflow
 * into the rest of the IV when incremented.
 */
void WBCRYPTO_ctr128_encrypt(const unsigned char *in, unsigned char *out,
                             size_t len, const void *key,
                             unsigned char ivec[16], unsigned char ecount_buf[16],
                             unsigned int *num, WBCRYPTO_block128_f block)
{
    unsigned int n;
    size_t l=0;

    assert(in && out && key && ecount_buf && num);
    assert(*num < 16);

    n = *num;

#if !defined(OPENSSL_SMALL_FOOTPRINT)
    if (16%sizeof(size_t) == 0) do { /* always true actually */
            while (n && len) {
                *(out++) = *(in++) ^ ecount_buf[n];
                --len;
                n = (n+1) % 16;
            }

#if defined(STRICT_ALIGNMENT)
            if (((size_t)in|(size_t)out|(size_t)ivec)%sizeof(size_t) != 0)
			break;
#endif
            while (len>=16) {
                (*block)(ivec, ecount_buf, key);
                ctr128_inc_aligned(ivec);
                for (; n<16; n+=sizeof(size_t))
                    *(size_t *)(out+n) =
                            *(size_t *)(in+n) ^ *(size_t *)(ecount_buf+n);
                len -= 16;
                out += 16;
                in  += 16;
                n = 0;
            }
            if (len) {
                (*block)(ivec, ecount_buf, key);
                ctr128_inc_aligned(ivec);
                while (len--) {
                    out[n] = in[n] ^ ecount_buf[n];
                    ++n;
                }
            }
            *num = n;
            return;
        } while(0);
    /* the rest would be commonly eliminated by x86* compiler */
#endif
    while (l<len) {
        if (n==0) {
            (*block)(ivec, ecount_buf, key);
            ctr128_inc(ivec);
        }
        out[l] = in[l] ^ ecount_buf[n];
        ++l;
        n = (n+1) % 16;
    }

    *num=n;
}

/* increment upper 96 bits of 128-bit counter by 1 */
static void ctr96_inc(unsigned char *counter) {
    u32 n=12;
    u8  c;

    do {
        --n;
        c = counter[n];
        ++c;
        counter[n] = c;
        if (c) return;
    } while (n);
}

void WBCRYPTO_ctr128_encrypt_ctr32(const unsigned char *in, unsigned char *out,
                                   size_t len, const void *key,
                                   unsigned char ivec[16], unsigned char ecount_buf[16],
                                   unsigned int *num, WBCRYPTO_ctr128_f func)
{
    unsigned int n,ctr32;

    assert(in && out && key && ecount_buf && num);
    assert(*num < 16);

    n = *num;

    while (n && len) {
        *(out++) = *(in++) ^ ecount_buf[n];
        --len;
        n = (n+1) % 16;
    }

    ctr32 = GETU32(ivec+12);
    while (len>=16) {
        size_t blocks = len/16;
        /*
         * 1<<28 is just a not-so-small yet not-so-large number...
         * Below condition is practically never met, but it has to
         * be checked for code correctness.
         */
        if (sizeof(size_t)>sizeof(unsigned int) && blocks>(1U<<28))
            blocks = (1U<<28);
        /*
         * As (*func) operates on 32-bit counter, caller
         * has to handle overflow. 'if' below detects the
         * overflow, which is then handled by limiting the
         * amount of blocks to the exact overflow point...
         */
        ctr32 += (u32)blocks;
        if (ctr32 < blocks) {
            blocks -= ctr32;
            ctr32   = 0;
        }
        (*func)(in,out,blocks,key,ivec);
        /* (*ctr) does not update ivec, caller does: */
        PUTU32(ivec+12,ctr32);
        /* ... overflow was detected, propogate carry. */
        if (ctr32 == 0)	ctr96_inc(ivec);
        blocks *= 16;
        len -= blocks;
        out += blocks;
        in  += blocks;
    }
    if (len) {
        memset(ecount_buf,0,16);
        (*func)(ecount_buf,ecount_buf,1,key,ivec);
        ++ctr32;
        PUTU32(ivec+12,ctr32);
        if (ctr32 == 0)	ctr96_inc(ivec);
        while (len--) {
            out[n] = in[n] ^ ecount_buf[n];
            ++n;
        }
    }

    *num=n;
}
