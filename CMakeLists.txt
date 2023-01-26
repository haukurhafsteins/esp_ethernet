idf_component_register(SRCS "ethernet.c"
                    INCLUDE_DIRS "include"
                    PRIV_REQUIRES "cjson" "nvsstorage" "nvs_flash")