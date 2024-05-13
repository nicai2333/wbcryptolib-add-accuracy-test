add_executable(
	sample_keybox_wbsm2
	sample_keybox_wbsm2.c
	commons/sample_common_drbg.c
	commons/sample_common_keys.c
)

target_link_libraries(
	sample_keybox_wbsm2
	PRIVATE
	wbcrypto
)