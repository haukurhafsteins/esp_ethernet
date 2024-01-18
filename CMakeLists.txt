idf_component_register(SRCS "ethernet.c"
                    INCLUDE_DIRS "include"
                    REQUIRES esp_netif esp_wifi esp_eth mdns
                    PRIV_REQUIRES "cJSON")
