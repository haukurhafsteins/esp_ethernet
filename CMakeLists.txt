# esp_driver_spi/gpio: ESP-IDF v6.0 removed them from the `driver` umbrella (HMO-113).
set(ESP_ETHERNET_REQUIRES esp_netif esp_wifi esp_eth mdns driver esp_driver_spi esp_driver_gpio)

# The W5500 SPI Ethernet driver left esp_eth in v6.0 for the esp-eth-drivers repo; it is the
# managed component espressif/w5500, registered here as espressif__w5500. Before v6.0 the
# driver is part of esp_eth and no extra requirement exists (HMO-113).
if(IDF_VERSION_MAJOR GREATER_EQUAL 6)
    list(APPEND ESP_ETHERNET_REQUIRES espressif__w5500)
endif()

idf_component_register(SRCS "discovery.c" "ethernet.c" "eth_spi_dma.c"
                    INCLUDE_DIRS "include"
                    REQUIRES ${ESP_ETHERNET_REQUIRES}
                    PRIV_REQUIRES "cJSON")
