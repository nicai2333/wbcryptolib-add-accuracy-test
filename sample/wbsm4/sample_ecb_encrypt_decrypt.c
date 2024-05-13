/**
 * Sample: Encrypt & Decrypt
 * this sample demonstrates the capability of encrypt & decrypt with WBSM4 algorithm
 */

#include "wbcrypto/wbsm4.h"
#include "commons/sample_common_keys.h"
#include "hex_utils.h"

#define ASSERT_SUCCESS(func)       \
    do                           \
    {                            \
        if( ( ret = (func) ) != 0 ) \
            goto cleanup;        \
    } while( 0 )

// instead of generating all the keys, we now load them manually to exhibit another way of doing it
//    this is done in sample_common_keys.c

//the plaintexts
char plaintext_buffer[] = "0123456789abcdef";
size_t plaintext_size = 16;

//the ciphertexts

uint8_t ciphertext_buffer[16] = {0};

uint8_t recovered_buffer[16] = {0};


int sample_ecb_encryption() {
    int ret;

    //run encrypt algorithm
    ASSERT_SUCCESS(wbcrypto_wbsm4_ecb_encrypt(&enc_ctx, plaintext_buffer, ciphertext_buffer));

    //done!
    printf("encryption success!\n");
    print_buf_in_hex("ciphertext", ciphertext_buffer, sizeof(ciphertext_buffer));

    cleanup:
    return ret;
}


int sample_ecb_decryption() {
    int ret;

    //run encrypt algorithm
    ASSERT_SUCCESS(wbcrypto_wbsm4_ecb_decrypt(&dec_ctx, ciphertext_buffer, recovered_buffer));

    //done!
    printf("\ndecryption success!");
    print_buf_in_hex("\nplaintext", plaintext_buffer, plaintext_size);
    print_buf_in_hex("\nrecovered", recovered_buffer, sizeof(recovered_buffer));

    cleanup:
    return ret;
}

int main(){

    int ret;

    //setup
    ASSERT_SUCCESS(setup_wbsm4_keys());

    //run actual samples
    ASSERT_SUCCESS(sample_ecb_encryption());
    ASSERT_SUCCESS(sample_ecb_decryption());

    cleanup:
    return ret;


}