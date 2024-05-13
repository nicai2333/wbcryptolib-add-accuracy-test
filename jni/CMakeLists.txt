aux_source_directory(src JNI_SRCS)
aux_source_directory(src/wbcryptopp JNI_SRCS)
aux_source_directory(src/mbedtlspp JNI_SRCS)

add_subdirectory(lib/jnihpp)
add_subdirectory(lib/spdlog)

add_library(wbcryptoJNI SHARED
  ${JNI_SRCS}
)

target_link_libraries(wbcryptoJNI PRIVATE jnihpp)
target_link_libraries(wbcryptoJNI PRIVATE spdlog)
target_link_libraries(wbcryptoJNI PUBLIC wbcrypto)

target_include_directories(wbcryptoJNI PUBLIC "include")
target_include_directories(wbcryptoJNI PUBLIC "lib")
target_include_directories(wbcryptoJNI PUBLIC ${JNI_INCLUDE_DIRS})