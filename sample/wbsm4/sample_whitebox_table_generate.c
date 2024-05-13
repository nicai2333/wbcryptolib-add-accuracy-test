/**
 * Sample: generate WBSM4 whitebox table
 * this sample demonstrates how to generate WBSM4 whitebox table
 */
#include "wbcrypto/wbsm4_generator.h"
#include "wbcrypto/wbsm4.h"

#define ASSERT_SUCCESS(func)       \
    do                           \
    {                            \
        if( ( ret = (func) ) != 0 ) \
            goto cleanup;        \
    } while( 0 )

// run the whitebox table generate
int sample_whitebox_table_generator() {

    int ret;

    // whitebox table size
    size_t table_size;

    /* the userkey of sm4 algorithm, in whitebox sm4 algorithm
       the userkey will hide in the whitebox table
     */
    unsigned char key[16] = {
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    // pointer for save the whitebox table
    uint8_t *table_ptr = NULL;

    //generate whitebox table based on userkey, randseed
    ASSERT_SUCCESS(wbcrypto_wbsm4_gentable_enc_to_bit(&table_ptr, key, 1000, &table_size));

    cleanup:
        free(table_ptr);
        return ret;
}

int main() {
        int ret;
        //ASSERT_SUCCESS(sample_whitebox_table_generator());

        cleanup:
        return ret;
        //
    }