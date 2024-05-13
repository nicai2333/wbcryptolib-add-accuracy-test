// #include "wbcrypto/wbaes.h"
// #include "test_local.h"

// static const unsigned char key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
//                                       0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

// static const unsigned char msg[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
//                                       0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

// int test_wbaes()
// {
//     int i;
//     unsigned char iv[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
//     unsigned char aad[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
//     unsigned char cipher[16] = {0};
//     unsigned char msg1024[1024] = {0};
//     unsigned char cipher1024[1024] = {0};
//     unsigned char plain1024[1024] = {0};
//     for (i = 0; i < 1024; i++)
//     {
//         msg1024[i] = i & 0xff;
//     }
//     // encrypt one block
//     WBCRYPTO_aes_context aes_ctx;
//     WBCRYPTO_aes_init_key(&aes_ctx, key, sizeof(key));
//     WBCRYPTO_aes_encrypt(msg, cipher, &aes_ctx);
//     TEST_print_state(cipher, sizeof(cipher));

//     // encrypt 64 blocks
//     WBCRYPTO_gcm_context *gcm_enc, *gcm_dec;
//     gcm_enc = WBCRYPTO_aes_gcm_init(&aes_ctx);
//     wbcrypto_wbaes_gcm_setiv(gcm_enc, iv, sizeof(iv));
//     wbcrypto_wbaes_gcm_aad(gcm_enc, aad, sizeof(aad));
//     wbcrypto_wbaes_gcm_encrypt(gcm_enc, msg1024, sizeof(msg1024), cipher1024, sizeof(cipher1024));
//     TEST_print_state(cipher1024, sizeof(cipher1024));

//     // decrypt 64 blocks
//     gcm_dec = WBCRYPTO_aes_gcm_init(&aes_ctx);
//     wbcrypto_wbaes_gcm_setiv(gcm_dec, iv, sizeof(iv));
//     wbcrypto_wbaes_gcm_aad(gcm_dec, aad, sizeof(aad));
//     wbcrypto_wbaes_gcm_decrypt(gcm_dec, cipher1024, sizeof(cipher1024), plain1024, sizeof(plain1024));
//     TEST_print_state(plain1024, sizeof(plain1024));

//     //free gcm ctx
//     wbcrypto_wbaes_gcm_free(gcm_enc);
//     wbcrypto_wbaes_gcm_free(gcm_dec);
// }

// int main()
// {
//     test_wbaes();
// }