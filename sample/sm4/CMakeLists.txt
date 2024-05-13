add_executable(
        sample_sm4_gcm_enc_dec
        sample_sm4_gcm_enc_dec.c
)

target_link_libraries(
        sample_sm4_gcm_enc_dec
        PRIVATE
        wbcrypto
)