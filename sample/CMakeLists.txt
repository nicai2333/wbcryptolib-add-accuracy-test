add_executable(samplespeedtest sample_speed_test.c)
target_link_libraries(samplespeedtest PRIVATE wbcrypto)

if(ENABLE_WBSM2)
    add_subdirectory(wbsm2)
endif()

if(ENABLE_KEYBOX AND ENABLE_WBSM2)
    add_subdirectory(keybox_wbsm2)
endif()

if(ENABLE_WBSM4)
    add_subdirectory(wbsm4)
endif()

if(ENABLE_WBAES)
    add_subdirectory(wbaes)
endif()

if(ENABLE_SM4)
    add_subdirectory(sm4)
endif()

if(ENABLE_SM2)
    add_subdirectory(sm2)
endif()

if(ENABLE_SM2COOP)
    add_subdirectory(sm2coop)
endif()