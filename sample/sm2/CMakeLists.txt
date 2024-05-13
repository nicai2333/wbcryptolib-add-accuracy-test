add_executable(
	sample_sm2_enc_dec
	sample_sm2_encrypt_decrypt.c
)

target_link_libraries(
	sample_sm2_enc_dec
	PRIVATE
	wbcrypto
)
