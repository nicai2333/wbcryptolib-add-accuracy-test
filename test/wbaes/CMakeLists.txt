if(ENABLE_WBAES)
    add_executable(aestest test/wbaes/test_local.c test/wbaes/aes_test.c)
    target_link_libraries(aestest PRIVATE wbcrypto)
    add_test(AES::Test aestest)

    add_executable(wbaestest test/wbaes/test_local.c test/wbaes/wbaes_test.c)
    target_link_libraries(wbaestest PRIVATE wbcrypto)
    add_test(WBAES::Test wbaestest)
endif()