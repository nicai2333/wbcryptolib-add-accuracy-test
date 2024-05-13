#include "../hex_utils.h"
#include <string.h>
#include <stdio.h>
#include "wbcrypto/wbsm2.h"
#include "crypto/speed.h"

#define TEST_MSG "abcdefghijklmnopqrstyvwxyz1234567890"

wbcrypto_wbsm2_public_key pubkey;
wbcrypto_wbsm2_private_key_segment A, B;
size_t olen = 0; // output len
unsigned char input[16384]={0};
unsigned char output[99999];
char rand_value[] = "4C62EEFD6ECFC2B95B92FD6C3D9575148AFA17425546D49018E5388D49DD7B4F";
wbcrypto_wbsm2_sign_session sign_ctx;

// 对大小为size字节的块进行循环加密，返回可以循环加密执行的次数
size_t test_kssm2_sign_loop(size_t size){
    size_t count = 0;
    for (count = 0; run && count < 0xffffffffffffffff; count++)
    {
        wbcrypto_wbsm2_sign_stepA(
			&pubkey,
			&A,
			&sign_ctx,
			input, size,
			mock_rand_hex, rand_value
		);
		wbcrypto_wbsm2_sign_stepB(
			&pubkey,
			&B,
			&sign_ctx,
			mock_rand_hex, rand_value
		);
		wbcrypto_wbsm2_sign_complete(
			&pubkey,
			&A,
			&sign_ctx,
			output, sizeof(output), &olen
		);
    }
   
    return count;
}
size_t test_kssm2_verify_loop(size_t size){
    size_t count = 0;
    for (count = 0; run && count < 0xffffffffffffffff; count++)
    {
       wbcrypto_wbsm2_verify(
		&pubkey,
		input, size,
		output, olen
		);
    }
   
    return count;
}

int main() {
    //global variables init
    wbcrypto_wbsm2_public_key_init(&pubkey);
	wbcrypto_wbsm2_load_default_group(&pubkey.grp);
	wbcrypto_wbsm2_private_key_segment_init(&A);
	wbcrypto_wbsm2_private_key_segment_init(&B);
    wbcrypto_wbsm2_generate_key(&pubkey,&A, &B,mock_rand_hex, rand_value);
    wbcrypto_wbsm2_sign_session_init(&sign_ctx);
    
    int ret = 0;
    size_t size = 32;
    
	printf("\nkssm2:\n");
    performance_test_sv(test_kssm2_sign_loop, test_kssm2_verify_loop, &size, 1, 10);

    //global variables free
    wbcrypto_wbsm2_public_key_free(&pubkey);
	wbcrypto_wbsm2_private_key_segment_free(&A);
	wbcrypto_wbsm2_private_key_segment_free(&B);
    wbcrypto_wbsm2_sign_session_free(&sign_ctx);
    return ret;
}