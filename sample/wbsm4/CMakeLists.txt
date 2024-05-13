add_executable(
        sample_wbsm4_whitebox_table_generate
        sample_whitebox_table_generate.c
)

target_link_libraries(
        sample_wbsm4_whitebox_table_generate
        PRIVATE
        wbcrypto
)


add_executable(
        sample_wbsm4_ecb_encrypt_decrypt
        sample_ecb_encrypt_decrypt.c
        commons/sample_common_keys.c
)

target_link_libraries(
        sample_wbsm4_ecb_encrypt_decrypt
        PRIVATE
        wbcrypto
)


add_executable(
        sample_wbsm4_cbc_encrypt_decrypt
        sample_cbc_encrypt_decrypt.c
        commons/sample_common_keys.c
)

target_link_libraries(
        sample_wbsm4_cbc_encrypt_decrypt
        PRIVATE
        wbcrypto
)

add_executable(
        sample_wbsm4_gcm_encrypt_decrypt
        sample_gcm_encrypt_decrypt.c
        commons/sample_common_keys.c
)

target_link_libraries(
        sample_wbsm4_gcm_encrypt_decrypt
        PRIVATE
        wbcrypto
)

add_executable(
        sample_wbsm4_xl_la
        sample_wbsm4_xl_la.c
)

target_link_libraries(
        sample_wbsm4_xl_la
        PRIVATE
        wbcrypto
)

add_executable(
        sample_wbsm4_xl
        sample_wbsm4_xl.c
)

target_link_libraries(
        sample_wbsm4_xl
        PRIVATE
        wbcrypto
)

add_executable(
        sample_wbsm4_se
        sample_wbsm4_se.c
)

target_link_libraries(
        sample_wbsm4_se
        PRIVATE
        wbcrypto
)