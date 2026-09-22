idf_component_register(SRCS "discovery.c" "ethernet.c" "eth_spi_dma.c"
                    INCLUDE_DIRS "include"
                    REQUIRES esp_netif esp_wifi esp_eth mdns driver
                    PRIV_REQUIRES "cJSON")
