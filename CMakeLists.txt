cmake_minimum_required (VERSION 3.8)

project(wbcrypto)

include(requireFlag.cmake)

# c11编译
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC -fopenmp")

# options #
set(ENABLE_SM3 OFF)
set(ENABLE_SM2 OFF)
set(ENABLE_MD OFF)
set(ENABLE_SM2COOP OFF)
set(ENABLE_RSACOOP OFF)
set(ENABLE_JNI OFF)
set(ENABLE_SM4 ON)
set(ENABLE_SM4_BS ON)
set(ENABLE_WBSM4 ON)
set(ENABLE_WBSM2 OFF)
set(ENABLE_KEYBOX OFF)
set(ENABLE_SAMPLE ON)
set(ENABLE_WBAES ON)
set(ENABLE_ECDSACOOP OFF)

# enable_test
set(ENABLE_TEST ON)

# libraries subdir #

# mbedtls
#cmake_policy(SET CMP0076 OLD)
#cmake_policy(SET CMP0077 OLD)
set(ENABLE_PROGRAMS OFF)
add_subdirectory(lib/mbedtls EXCLUDE_FROM_ALL)

# main library #
set(LIBRARY_OUTPUT_PATH "${PROJECT_BINARY_DIR}/out")
add_library(wbcrypto SHARED src/dummy.c)

# includes
target_include_directories(wbcrypto PUBLIC include)
# sources
# add wbmatrix sources
aux_source_directory(src/wbmatrix WBMATRIX_SRC)
target_sources(wbcrypto PRIVATE ${WBMATRIX_SRC})

target_sources(wbcrypto PRIVATE src/asn1/asn1_utils.c)

aux_source_directory(src/speed_test SPEED_TEST_SRC)
target_sources(wbcrypto PRIVATE ${SPEED_TEST_SRC})

if(ENABLE_SM2)
	aux_source_directory(src/sm2 SM2_SRC)
	target_sources(wbcrypto PRIVATE ${SM2_SRC})
endif()
if(ENABLE_MD)
	aux_source_directory(src/md MD_SRC)
	target_sources(wbcrypto PRIVATE ${MD_SRC})
endif()

if(ENABLE_ECDSACOOP)
	aux_source_directory(src/ecdsacoop ECDSACOOP_SRC)
	target_sources(wbcrypto PRIVATE ${ECDSACOOP_SRC})
endif()

if(ENABLE_RSACOOP)
	aux_source_directory(src/rsacoop RSACOOP_SRC)
	target_sources(wbcrypto PRIVATE ${RSACOOP_SRC})
endif()
if(ENABLE_SM2COOP)
	require_flag(ENABLE_SM2 "sm2coop algorithm requires sm2 to work!")
	aux_source_directory(src/sm2coop SM2COOP_SRC)
	target_sources(wbcrypto PRIVATE ${SM2COOP_SRC})
endif()
if(ENABLE_WBSM2)
	require_flag(ENABLE_SM2COOP "wbsm2 algorithm requires sm2coop to work!")
	aux_source_directory(src/wbsm2 WBSM2_SRC)
	target_sources(wbcrypto PRIVATE ${WBSM2_SRC})
endif()
if(ENABLE_SM3)
	target_sources(wbcrypto PRIVATE src/sm3/sm3.c)
endif()
if(ENABLE_SM4)
	aux_source_directory(src/sm4 SM4_SRC)
	target_sources(wbcrypto PRIVATE ${SM4_SRC})
endif()
if(ENABLE_SM4_BS)
	# set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c++11 -O3 -g -m64 -mavx2")
	set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 -g -O2 -m64 -mavx2 ")
	# set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c++11 -O2 -g -m64 -mavx2 -mavx512bw -mavx512f")
	# set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 -O2 -g  -m64 -mavx2 -mavx512f")
	# set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2 -march=armv8-a+fp+simd+crypto+crc")
	aux_source_directory(src/sm4_bs SM4_BS_SRC)
	target_sources(wbcrypto PRIVATE ${SM4_BS_SRC})
endif()
if(ENABLE_WBSM4)
	require_flag(ENABLE_SM4 "wbsm4 algorithm requires sm4 to work!")
	aux_source_directory(src/modes WBSM4_SRC)
	aux_source_directory(src/wbsm4 WBSM4_SRC)
	aux_source_directory(src/wbmatrix WBSM4_SRC)
	target_sources(wbcrypto PRIVATE ${WBSM4_SRC})
endif()
if(ENABLE_WBAES)
	aux_source_directory(src/wbaes WBAES_SRC)
	target_sources(wbcrypto PRIVATE ${WBAES_SRC})
endif()


if(ENABLE_KEYBOX)
	require_flag(ENABLE_SM4 "keybox requires SM4 to work!")
endif()

if(ENABLE_KEYBOX AND ENABLE_WBSM2)
	aux_source_directory(src/keybox_wbsm2 KEYBOX_WBSM2_SRC)
	target_sources(wbcrypto PRIVATE ${KEYBOX_WBSM2_SRC})
endif()

# libraries
target_link_libraries(wbcrypto PUBLIC mbedtls)

if(ENABLE_JNI)
find_package(JNI REQUIRED)
add_subdirectory(jni)
endif()

if(ENABLE_TEST)
	enable_testing()
	add_subdirectory(test)
endif()
# test subdir #

# samples #
if(ENABLE_SAMPLE)
	add_subdirectory(sample)
endif()
