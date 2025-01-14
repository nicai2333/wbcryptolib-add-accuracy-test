// #include "wbcrypto/wbaes_modes.h"

// // multiplication in GF(2^128)
// static void gcm_mult( WBCRYPTO_gcm_context *ctx,
//                       const unsigned char x[16],
//                       unsigned char output[16] )
// {
//     int i;
//     unsigned char lo, hi, rem;
//     uint64_t zh, zl;

//     lo = (unsigned char)( x[15] & 0x0f );
//     hi = (unsigned char)( x[15] >> 4 );
//     zh = ctx->HH[lo];
//     zl = ctx->HL[lo];

//     for( i = 15; i >= 0; i-- ) {
//         lo = (unsigned char) ( x[i] & 0x0f );
//         hi = (unsigned char) ( x[i] >> 4 );

//         if( i != 15 ) {
//             rem = (unsigned char) ( zl & 0x0f );
//             zl = ( zh << 60 ) | ( zl >> 4 );
//             zh = ( zh >> 4 );
//             zh ^= (uint64_t) last4[rem] << 48;
//             zh ^= ctx->HH[lo];
//             zl ^= ctx->HL[lo];
//         }
//         rem = (unsigned char) ( zl & 0x0f );
//         zl = ( zh << 60 ) | ( zl >> 4 );
//         zh = ( zh >> 4 );
//         zh ^= (uint64_t) last4[rem] << 48;
//         zh ^= ctx->HH[hi];
//         zl ^= ctx->HL[hi];
//     }
//     PUT_UINT32_BE( zh >> 32, output, 0 );
//     PUT_UINT32_BE( zh, output, 4 );
//     PUT_UINT32_BE( zl >> 32, output, 8 );
//     PUT_UINT32_BE( zl, output, 12 );
// }

// WBCRYPTO_gcm_context *WBCRYPTO_gcm_init(void *key, block128_f block)
// {
//     struct gcm128_context *ctx;
//     int i, j;
//     uint64_t hi, lo;
//     uint64_t vl, vh;
//     unsigned char h[16];

//     ctx=malloc(sizeof(struct gcm128_context));  
//     if(ctx==NULL){
//         return NULL;
//     }
//     memset( ctx, 0, sizeof(WBCRYPTO_gcm_context) );  // zero caller-provided GCM context
//     memset( h, 0, 16 );                     // initialize the block to encrypt

//     ctx->key=key;
//     ctx->block=block;

//     // encrypt the null 128-bit block to generate a key-based value
//     // which is then used to initialize our GHASH lookup tables
//     (*block) (h, h, key);

//     GET_UINT32_BE( hi, h,  0  );    // pack h as two 64-bit ints, big-endian
//     GET_UINT32_BE( lo, h,  4  );
//     vh = (uint64_t) hi << 32 | lo;

//     GET_UINT32_BE( hi, h,  8  );
//     GET_UINT32_BE( lo, h,  12 );
//     vl = (uint64_t) hi << 32 | lo;

//     ctx->HL[8] = vl;                // 8 = 1000 corresponds to 1 in GF(2^128)
//     ctx->HH[8] = vh;
//     ctx->HH[0] = 0;                 // 0 corresponds to 0 in GF(2^128)
//     ctx->HL[0] = 0;

//     for( i = 4; i > 0; i >>= 1 ) {
//         uint32_t T = (uint32_t) ( vl & 1 ) * 0xe1000000U;
//         vl  = ( vh << 63 ) | ( vl >> 1 );
//         vh  = ( vh >> 1 ) ^ ( (uint64_t) T << 32);
//         ctx->HL[i] = vl;
//         ctx->HH[i] = vh;
//     }
//     for (i = 2; i < 16; i <<= 1 ) {
//         uint64_t *HiL = ctx->HL + i, *HiH = ctx->HH + i;
//         vh = *HiH;
//         vl = *HiL;
//         for( j = 1; j < i; j++ ) {
//             HiH[j] = vh ^ ctx->HH[j];
//             HiL[j] = vl ^ ctx->HL[j];
//         }
//     }
//     return ctx;
// }

// int wbcrypto_wbaes_gcm_setiv(WBCRYPTO_gcm_context *ctx,
//                           const unsigned char *iv, size_t len){
//     int ret=0;            // our error return if encrypting fails
//     unsigned char work_buf[16]; // XOR source built from provided IV if len != 16
//     const unsigned char *p;     // general purpose array pointer
//     size_t use_len;     // byte count to process, up to 16 bytes
//     size_t i;           // local loop iterator
//     block128_f block = ctx->block;
//     void *key = ctx->key;

//     // since the context might be reused under the same key
//     // we zero the working buffers for this next new process
//     memset( ctx->y,   0x00, sizeof(ctx->y  ) );
//     memset( ctx->buf, 0x00, sizeof(ctx->buf) );
//     ctx->len = 0;

//     if( len == 12 ) {                // GCM natively uses a 12-byte, 96-bit IV
//         memcpy( ctx->y, iv, len );   // copy the IV to the top of the 'y' buff
//         ctx->y[15] = 1;                 // start "counting" from 1 (not 0)
//     }
//     else    // if we don't have a 12-byte IV, we GHASH whatever we've been given
//     {
//         memset( work_buf, 0x00, 16 );               // clear the working buffer
//         PUT_UINT32_BE( len * 8, work_buf, 12 );  // place the IV into buffer

//         p = iv;
//         while( len > 0 ) {
//             use_len = ( len < 16 ) ? len : 16;
//             for( i = 0; i < use_len; i++ ) ctx->y[i] ^= p[i];
//             gcm_mult( ctx, ctx->y, ctx->y );
//             len -= use_len;
//             p += use_len;
//         }
//         for( i = 0; i < 16; i++ ) ctx->y[i] ^= work_buf[i];
//         gcm_mult( ctx, ctx->y, ctx->y );
//     }
//     (*block) (ctx->y, ctx->base_ectr, key);
//     ret=1;
// cleanup:
//     return ret;
// }

// int wbcrypto_wbaes_gcm_aad(WBCRYPTO_gcm_context *ctx,
//                         const unsigned char *aad, size_t len){
//     int ret=0;            // our error return if the AES encrypt fails
//     const unsigned char *p;     // general purpose array pointer
//     size_t use_len;     // byte count to process, up to 16 bytes
//     size_t i;           // local loop iterator
//     block128_f block = ctx->block;
//     void *key = ctx->key;

//     ctx->add_len = len;
//     p = aad;
//     while( len > 0 ) {
//         use_len = ( len < 16 ) ? len : 16;
//         for( i = 0; i < use_len; i++ ) ctx->buf[i] ^= p[i];
//         gcm_mult( ctx, ctx->buf, ctx->buf );
//         len -= use_len;
//         p += use_len;
//     }
//     ret=1;
// cleanup:
//     return ret;
// }

// int wbcrypto_wbaes_gcm_encrypt(WBCRYPTO_gcm_context *ctx,
//                             const unsigned char *in, size_t inlen,
//                             unsigned char *out, size_t outlen){
//     int ret=0, len;            // our error return if the AES encrypt fails
//     if(outlen<inlen){
//         return -1;
//     }else{
//         len=inlen;
//     }
//     unsigned char ectr[16];     // counter-mode cipher output for XORing
//     size_t use_len;     // byte count to process, up to 16 bytes
//     size_t i;           // local loop iterator
//     block128_f block = ctx->block;
//     void *key = ctx->key;

//     ctx->len += len; // bump the GCM context's running length count

//     while( len > 0 ) {
//         // clamp the length to process at 16 bytes
//         use_len = ( len < 16 ) ? len : 16;

//         // increment the context's 128-bit IV||Counter 'y' vector
//         for( i = 16; i > 12; i-- ) if( ++ctx->y[i - 1] != 0 ) break;

//         // encrypt the context's 'y' vector under the established key
//         (*block) (ctx->y, ectr, key);

//         // encrypt or decrypt the input to the output
//         for( i = 0; i < use_len; i++ ) {
//             // XOR the cipher's ouptut vector (ectr) with our input
//             out[i] = (unsigned char) ( ectr[i] ^ in[i] );
//             // now we mix in our data into the authentication hash.
//             // if we're ENcrypting we XOR in the post-XOR (output)
//             // results, but if we're DEcrypting we XOR in the input
//             // data
//             ctx->buf[i] ^= out[i];
//         }

//         gcm_mult( ctx, ctx->buf, ctx->buf );    // perform a GHASH operation

//         len -= use_len;  // drop the remaining byte count to process
//         in  += use_len;  // bump our input pointer forward
//         out += use_len;  // bump our output pointer forward
//     }
//     ret=1;
// cleanup:
//     return ret;
// }

// int wbcrypto_wbaes_gcm_decrypt(WBCRYPTO_gcm_context *ctx,
//                             const unsigned char *in, size_t inlen,
//                             unsigned char *out, size_t outlen){
//     int ret=0, len;            // our error return if the AES encrypt fails
//     if(outlen<inlen){
//         return -1;
//     }else{
//         len=inlen;
//     }
//     unsigned char ectr[16];     // counter-mode cipher output for XORing
//     size_t use_len;     // byte count to process, up to 16 bytes
//     size_t i;           // local loop iterator
//     block128_f block = ctx->block;
//     void *key = ctx->key;

//     ctx->len += len; // bump the GCM context's running length count

//     while( len > 0 ) {
//         // clamp the length to process at 16 bytes
//         use_len = ( len < 16 ) ? len : 16;

//         // increment the context's 128-bit IV||Counter 'y' vector
//         for( i = 16; i > 12; i-- ) if( ++ctx->y[i - 1] != 0 ) break;

//         // encrypt the context's 'y' vector under the established key
//         (*block) (ctx->y, ectr, key);

//         // encrypt or decrypt the input to the output
//         for( i = 0; i < use_len; i++ ) {
//             // but if we're DEcrypting we XOR in the input data first,
//             // i.e. before saving to ouput data, otherwise if the input
//             // and output buffer are the same (inplace decryption) we
//             // would not get the correct auth tag

//             ctx->buf[i] ^= in[i];

//             // XOR the cipher's ouptut vector (ectr) with our input
//             out[i] = (unsigned char) ( ectr[i] ^ in[i] );
//         }
//         gcm_mult( ctx, ctx->buf, ctx->buf );    // perform a GHASH operation

//         len -= use_len;  // drop the remaining byte count to process
//         in  += use_len;  // bump our input pointer forward
//         out += use_len;  // bump our output pointer forward
//     }
//     ret=1;
// cleanup:
//     return ret;
// }

// int wbcrypto_wbaes_gcm_finish(WBCRYPTO_gcm_context *ctx, unsigned char *tag,
//                             size_t len){
//     int ret=0;
//     unsigned char work_buf[16];
//     uint64_t orig_len     = ctx->len * 8;
//     uint64_t orig_add_len = ctx->add_len * 8;
//     size_t i;

//     if( len != 0 ) memcpy( tag, ctx->base_ectr, len );

//     if( orig_len || orig_add_len ) {
//         memset( work_buf, 0x00, 16 );

//         PUT_UINT32_BE( ( orig_add_len >> 32 ), work_buf, 0  );
//         PUT_UINT32_BE( ( orig_add_len       ), work_buf, 4  );
//         PUT_UINT32_BE( ( orig_len     >> 32 ), work_buf, 8  );
//         PUT_UINT32_BE( ( orig_len           ), work_buf, 12 );

//         for( i = 0; i < 16; i++ ) ctx->buf[i] ^= work_buf[i];
//         gcm_mult( ctx, ctx->buf, ctx->buf );
//         for( i = 0; i < len; i++ ) tag[i] ^= ctx->buf[i];
//     }
//     ret=1;
// cleanup:
//     return ret;
// }

// void wbcrypto_wbaes_gcm_free(WBCRYPTO_gcm_context *ctx){
//     memset( ctx, 0, sizeof(WBCRYPTO_gcm_context) );
//     if(ctx!=NULL){
//         free(ctx);
//         ctx=NULL;
//     }
// }