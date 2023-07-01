idf_component_register(SRCS "ethernet.c"
                    INCLUDE_DIRS "include"
                    REQUIRES esp_netif esp_wifi
                    PRIV_REQUIRES "cJSON")
