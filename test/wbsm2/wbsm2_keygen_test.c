#include "keygen.h"
#include "asserts.h"

char rand_value[] = "4C62EEFD6ECFC2B95B92FD6C3D9575148AFA17425546D49018E5388D49DD7B4F";


int test_keygen_whole_process_works() {
	int ret;
	wbcrypto_wbsm2_public_key pubkey;
	wbcrypto_wbsm2_private_key_segment A, B;
	
	wbcrypto_wbsm2_public_key_init(&pubkey);
	wbcrypto_wbsm2_load_default_group(&pubkey.grp);
	wbcrypto_wbsm2_private_key_segment_init(&A);
	wbcrypto_wbsm2_private_key_segment_init(&B);

	
	ASSERT_SUCCESS(keygen(&pubkey, &A, &B, rand_value));

	
cleanup:
	wbcrypto_wbsm2_public_key_free(&pubkey);
	wbcrypto_wbsm2_private_key_segment_free(&A);
	wbcrypto_wbsm2_private_key_segment_free(&B);
	return ret;
}

int main() {
	int ret;
	
	//integration
	ASSERT_SUCCESS(test_keygen_whole_process_works());
	
cleanup:
	return ret;
}
