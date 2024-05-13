add_executable(
	sample_wbsm2_keygen
	sample_keygen.c
	commons/sample_common_drbg.c
)

target_link_libraries(
	sample_wbsm2_keygen
	PRIVATE
	wbcrypto
)


add_executable(
	sample_wbsm2_encrypt_decrypt
	sample_encrypt_decrypt.c
	commons/sample_common_drbg.c
	commons/sample_common_keys.c
)

target_link_libraries(
	sample_wbsm2_encrypt_decrypt
	PRIVATE
	wbcrypto
)


add_executable(
	sample_wbsm2_sign_verify
	sample_sign_verify.c
	commons/sample_common_drbg.c
	commons/sample_common_keys.c
)

target_link_libraries(
	sample_wbsm2_sign_verify
	PRIVATE
	wbcrypto
)