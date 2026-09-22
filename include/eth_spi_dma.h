// eth_spi_dma.h - W5500 SPI driver that transmits frames from a preallocated DMA buffer.
//
// Drop-in replacement for the stock SPI driver inside esp_eth's W5500 MAC, wired
// through eth_w5500_config_t::custom_spi_driver. See eth_spi_dma.c for why.
#pragma once

#include "driver/spi_master.h"
#include "esp_err.h"

#ifdef __cplusplus
extern "C"
{
#endif

    /// @brief What eth_spi_dma_init() needs; point custom_spi_driver.config at one of these.
    typedef struct
    {
        spi_host_device_t spi_host_id;             ///< Bus the W5500 sits on, already initialised
        spi_device_interface_config_t *spi_devcfg; ///< Device config, same one the stock driver would take
    } eth_spi_dma_config_t;

    void *eth_spi_dma_init(const void *spi_config);
    esp_err_t eth_spi_dma_deinit(void *spi_ctx);
    esp_err_t eth_spi_dma_read(void *spi_ctx, uint32_t cmd, uint32_t addr, void *data, uint32_t len);
    esp_err_t eth_spi_dma_write(void *spi_ctx, uint32_t cmd, uint32_t addr, const void *data, uint32_t len);

#ifdef __cplusplus
}
#endif
