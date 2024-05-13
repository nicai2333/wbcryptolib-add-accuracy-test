add_executable(asn1utilstest asn1utils_test.c)
target_link_libraries(asn1utilstest PRIVATE wbcrypto)
add_test(ASN1UtilsTest asn1utilstest)

if(ENABLE_SM3)
    add_executable(sm3test  sm3_test.c)
    target_link_libraries(sm3test PRIVATE wbcrypto)
    add_test(SM3Test sm3test)
endif()

if(ENABLE_RSACOOP)
    add_executable(rsacooptest rsacoop_test.c)
    target_link_libraries(rsacooptest PRIVATE wbcrypto)
    add_test(RSACoopTest rsacooptest)
endif()

if(ENABLE_SM2COOP)
    add_executable(sm2coopperftest sm2coop_perf_test.cpp)
    target_compile_features(sm2coopperftest PRIVATE cxx_std_17)
    target_link_libraries(sm2coopperftest PRIVATE wbcrypto)
    add_test(Sm2Coop_Perf_Test sm2coopperftest)
endif()

if(ENABLE_SM4)
    add_executable(sm4test sm4_test.c)
    target_link_libraries(sm4test PRIVATE wbcrypto)
    add_test(SM4Test sm4test)
endif()

if(ENABLE_WBSM4)
    add_executable(wbsm4test wbsm4_test.c)
    target_link_libraries(wbsm4test PRIVATE wbcrypto)
    add_test(WBSM4Test wbsm4test)
endif()

if(ENABLE_SM4_BS)
    add_executable(sm4bstest sm4_bs_test.c)
    target_link_libraries(sm4bstest PRIVATE wbcrypto)
	add_executable(sm4bsrotest sm4_bs_ro_test.c)
    target_link_libraries(sm4bsrotest PRIVATE wbcrypto)
    add_test(SM4BSTest sm4bstest)
endif()

if(ENABLE_ECDSACOOP)
    add_executable(ecdsacooptest ecdsacoop_test.c)
    target_link_libraries(ecdsacooptest PRIVATE wbcrypto)
    add_test(ECDSACoopTest ecdsacooptest)
endif()

if(ENABLE_SM2)
	add_executable(sm2_encrypt_smoke_test ./sm2/sm2_encrypt_smoke_test.c)
	target_link_libraries(sm2_encrypt_smoke_test PRIVATE wbcrypto)
	add_test(SM2_Encrypt_SmokeTest sm2_encrypt_smoke_test)

	add_executable(sm2_sign_smoke_test ./sm2/sm2_sign_smoke_test.c)
	target_link_libraries(sm2_sign_smoke_test PRIVATE wbcrypto)
	add_test(SM2_Sign_SmokeTest sm2_sign_smoke_test)
endif()

if(ENABLE_WBSM2)
	add_executable(wbsm2_encrypt_decrypt_test ./wbsm2/wbsm2_encrypt_decrypt_test.c ./wbsm2/keygen.c)
	target_link_libraries(wbsm2_encrypt_decrypt_test PRIVATE wbcrypto)
	add_test(WBSM2_Encrypt_Test wbsm2_encrypt_decrypt_test)

	add_executable(wbsm2_sign_verify_test ./wbsm2/wbsm2_sign_verify_test.c ./wbsm2/keygen.c)
	target_link_libraries(wbsm2_sign_verify_test PRIVATE wbcrypto)
	add_test(WBSM2_Sign_Test wbsm2_sign_verify_test)

	add_executable(wbsm2_keygen_test ./wbsm2/wbsm2_keygen_test.c ./wbsm2/keygen.c)
	target_link_libraries(wbsm2_keygen_test PRIVATE wbcrypto)
	add_test(WBSM2_Keygen_Test wbsm2_keygen_test)
endif()

if(ENABLE_KEYBOX AND ENABLE_WBSM2)
	#basic test to ensure reader can read writer's result
	add_executable(keybox_wbsm2_asn1_io_test ./keybox_wbsm2/keybox_wbsm2_asn1_io_test.c)
	target_link_libraries(keybox_wbsm2_asn1_io_test PRIVATE wbcrypto)
	add_test(KeyBox_WBSM2_ASN1IO_Test keybox_wbsm2_asn1_io_test)

	#basic test 
	add_executable(keybox_wbsm2_test ./keybox_wbsm2/keybox_wbsm2_test.c)
	target_link_libraries(keybox_wbsm2_test PRIVATE wbcrypto)
	add_test(KeyBox_WBSM2_Test keybox_wbsm2_test)
endif()

if(ENABLE_SM2COOP)
	add_executable(sm2coop_encrypt_decrypt_test ./sm2coop/sm2coop_encrypt_decrypt_test.c ./sm2coop/keygen.c)
	target_link_libraries(sm2coop_encrypt_decrypt_test PRIVATE wbcrypto)
	add_test(SM2Coop_Encrypt_Test sm2coop_encrypt_decrypt_test)

	add_executable(sm2coop_sign_test ./sm2coop/sm2coop_sign_test.c ./sm2coop/keygen.c)
	target_link_libraries(sm2coop_sign_test PRIVATE wbcrypto)
	add_test(SM2Coop_Sign_Test sm2coop_sign_test)

	add_executable(sm2coop_keygen_test ./sm2coop/sm2coop_keygen_test.c ./sm2coop/keygen.c)
	target_link_libraries(sm2coop_keygen_test PRIVATE wbcrypto)
	add_test(SM2Coop_Keygen_Test sm2coop_keygen_test)

	add_executable(sm2coop_context_test ./sm2coop/sm2coop_context_test.c ./sm2coop/keygen.c)
	target_link_libraries(sm2coop_context_test PRIVATE wbcrypto)
	add_test(SM2Coop_Context_Test sm2coop_context_test)
endif()

if(ENABLE_WBAES)
    # add_executable(aestest ./wbaes/test_local.c ./wbaes/aes_test.c)
    # target_link_libraries(aestest PRIVATE wbcrypto)
    # add_test(AES_Test aestest)

    # add_executable(wbaestest ./wbaes/test_local.c ./wbaes/wbaes_test.c)
    # target_link_libraries(wbaestest PRIVATE wbcrypto)
    # add_test(WBAES_Test wbaestest)
endif()

add_executable(speed_test_wbaes ./speed/speed_test_wbaes.c)
target_link_libraries(speed_test_wbaes PRIVATE wbcrypto)

add_executable(speed_test_wbsm4sela ./speed/speed_test_wbsm4_se_la.c)
target_link_libraries(speed_test_wbsm4sela PRIVATE wbcrypto)

add_executable(speed_test_wbsm4se ./speed/speed_test_wbsm4_se.c)
target_link_libraries(speed_test_wbsm4se PRIVATE wbcrypto)

add_executable(speed_test_wbsm4xlla ./speed/speed_test_wbsm4_xl_la.c)
target_link_libraries(speed_test_wbsm4xlla PRIVATE wbcrypto)

add_executable(speed_test_sm4lut ./speed/speed_test_sm4_lut.c)
target_link_libraries(speed_test_sm4lut PRIVATE wbcrypto)

add_executable(muti_speed_test_wbaes ./muti_speed/muti_speed_test_wbaes.c)
target_link_libraries(muti_speed_test_wbaes PRIVATE wbcrypto)

add_executable(muti_speed_test_wbsm4se ./muti_speed/muti_speed_test_wbsm4_se.c)
target_link_libraries(muti_speed_test_wbsm4se PRIVATE wbcrypto)

add_executable(muti_speed_test_wbsm4xlla ./muti_speed/muti_speed_test_wbsm4_xl_la.c)
target_link_libraries(muti_speed_test_wbsm4xlla PRIVATE wbcrypto)

