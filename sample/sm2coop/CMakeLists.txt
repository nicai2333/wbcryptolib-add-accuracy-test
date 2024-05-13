SET(CMAKE_C_FLAGS "-O2 -fopenmp")
add_executable(
        sample_sm2coop_sign_verify
        sample_sm2coop_sign_verify.c
        keygen.c
)
target_link_libraries(
        sample_sm2coop_sign_verify
        PRIVATE
        wbcrypto
)

add_executable(
        sample_sm2coop_encrypt_decrypt
        sample_sm2coop_encrypt_decrypt.c
        keygen.c
)
target_link_libraries(
        sample_sm2coop_encrypt_decrypt
        PRIVATE
        wbcrypto
)