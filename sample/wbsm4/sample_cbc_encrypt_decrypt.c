/**
 * Sample: Encrypt & Decrypt
 * this sample demonstrates the capability of encrypt & decrypt with WBSM4 algorithm
 */
#include "hex_utils.h"
#include "wbcrypto/wbsm4.h"
#include "commons/sample_common_keys.h"

#define ASSERT_SUCCESS(func)       \
    do                           \
    {                            \
        if( ( ret = (func) ) != 0 ) \
            goto cleanup;        \
    } while( 0 )

// instead of generating all the keys, we now load them manually to exhibit another way of doing it
//    this is done in sample_common_keys.c

//the plaintexts
char plaintext_buffer[] = "White Box SM4 Crypto Algorithm";
size_t plaintext_size = 30;

//the ciphertexts

uint8_t ciphertext_buffer[30] = {0};

uint8_t recovered_buffer[30] = {0};


int sample_cbc_encryption() {
    int ret;

    //run encrypt algorithm, the IV in cbc mode are specified in "0123456789abcdef"
    // if want to customize IV,use the following method "wbcrypto_wbsm4_crypt_cbc()".
    ASSERT_SUCCESS(wbcrypto_wbsm4_cbc_encrypt(&enc_ctx, plaintext_size, plaintext_buffer, ciphertext_buffer));

    //done!
    printf("encryption success!\n");
    print_buf_in_hex("ciphertext", ciphertext_buffer, sizeof(ciphertext_buffer));

    cleanup:
    return ret;
}


int sample_cbc_decryption() {
    int ret;

    //run decrypt algorithm, the IV in cbc mode are specified in "0123456789abcdef"
    // if want to customize IV,use the following method "wbcrypto_wbsm4_crypt_cbc()".
    ASSERT_SUCCESS(wbcrypto_wbsm4_cbc_decrypt(&dec_ctx, plaintext_size, ciphertext_buffer, recovered_buffer));

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
    ASSERT_SUCCESS(sample_cbc_encryption());
    ASSERT_SUCCESS(sample_cbc_decryption());

    cleanup:
    return ret;



}