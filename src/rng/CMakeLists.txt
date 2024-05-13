aux_source_directory(. RNG_SRC)
aux_source_directory(./rng RNG_SRC)
target_sources(wbcrypto PUBLIC ${RNG_SRC})