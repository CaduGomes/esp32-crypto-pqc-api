set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DWOLFSSL_USER_SETTINGS")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DWOLFSSL_USER_SETTINGS")

idf_component_register(SRCS "src/CryptoAPI.cpp"
                            "src/WolfsslModule.cpp"
                            "src/MbedtlsModule.cpp"
                            "src/MicroeccModule.cpp"
                            "src/CryptoApiCommons.cpp"
                     INCLUDE_DIRS "include"
                     REQUIRES wolfssl mbedtls micro-ecc esp_timer)
