#include <ctype.h>
#include <string.h>
#include <stdint.h>
#include "crypto/sm2.h"
#include "wbcrypto/internal/sm2/sm2_utils.h"
#include "test_data.h"
#include "../hex_utils.h"

void sample_enc_dec_rawbytes() {
	wbcrypto_sm2_context ctx;
	int ret = 0;
	unsigned char plaintext[] = {0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0xa};
	size_t p_len = 10;
	unsigned char ciphertext[1024];
	size_t c_len;
	unsigned char out_buf[1024];
	size_t out_len;
	char encrypt_rand_value[] = "rand_value1";
	char gen_key_rand_value[] = "rand_value2";

	// initialize ctx with sm2p256v1 group parameter
	wbcrypto_sm2_context_init(&ctx);

	// generate key
	wbcrypto_sm2_gen_keypair(&ctx, mock_rand_hex, gen_key_rand_value);

	print_buf_in_hex("plaintext", plaintext, p_len);

	// encrypt
	wbcrypto_sm2_encrypt_rawBytes(
		&ctx,
		plaintext, p_len,
		ciphertext, sizeof(ciphertext), &c_len,
		mock_rand_hex, encrypt_rand_value
	);

	print_buf_in_hex("encrypted_text", ciphertext, c_len);
	
	// decrypt
	wbcrypto_sm2_decrypt_rawBytes(
		&ctx,
		ciphertext, c_len,
		out_buf, sizeof(out_buf), &out_len
	);
	print_buf_in_hex("decrypted_text", out_buf, out_len);

	wbcrypto_sm2_context_free(&ctx);
}

int main() {

	sample_enc_dec_rawbytes();
	
	return 0;
}