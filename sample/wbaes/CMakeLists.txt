add_executable(
        sample_wbaes
        sample_wbaes.c
)

target_link_libraries(
        sample_wbaes
        PRIVATE
        wbcrypto
)

