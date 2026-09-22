// eth_spi_dma.c - W5500 SPI driver that transmits frames from a preallocated DMA buffer.
//
// The stock driver in esp_eth (esp_eth_mac_w5500.c, w5500_spi_write) hands the
// caller's pointer straight to spi_device_polling_transmit as tx_buffer. For a frame
// write that pointer is the lwIP payload: arbitrary address, arbitrary length. The SPI
// master then cannot use it directly and bounces it through
//
//     heap_caps_aligned_alloc(alignment, align_len, MALLOC_CAP_DMA | MALLOC_CAP_INTERNAL)
//
// on *every* transmit. Under web-page load, with httpd and lwIP holding internal RAM
// and only CONFIG_SPIRAM_MALLOC_RESERVE_INTERNAL left for internal-only requests, that
// ~1.5 KB aligned allocation starts failing against a fragmented heap and frames drop:
//
//     E spi_master: setup_dma_priv_buffer(1214): Failed to allocate priv TX buffer
//     E w5500.mac:  w5500_spi_write(146): spi transmit failed
//     E w5500.mac:  emac_w5500_transmit(638): write frame failed
//
// This driver keeps one aligned, DMA-capable buffer for the life of the link and copies
// each frame into it, so the transmit path allocates nothing at all.
//
// Register writes stay on the plain path: they are a few bytes each, they are not what
// failed, and padding them would be unsafe (the W5500 auto-increments its address, so
// trailing bytes would land in the next register). Reads are left alone too - the MAC
// reads into its own long-lived rx_buffer and no "priv RX buffer" failure has been seen.
#include <string.h>

#include "eth_spi_dma.h"

#include "esp_heap_caps.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

static const char *TAG = "eth_spi_dma";

// Mirrors of the W5500 SPI frame layout in esp_eth's private w5500.h. The MAC packs the
// block select bits into the address phase, which is what lets us tell a frame write to
// socket memory from a register write.
#define W5500_BSB_OFFSET (3)
#define W5500_BSB_SOCK_TX_BUF(s) ((s) * 4 + 2)
#define W5500_TX_MEM_SIZE (0x4000) // Socket 0 TX ring, must match the MAC's own view

// Buffer and transfer length are both rounded to this. The SPI master requires the TX
// pointer *and*, when a cache is in play, the length to meet the DMA/cache alignment of
// the bus; 64 is a multiple of every alignment this part can ask for, so padding to it
// avoids the bounce without having to query the bus through a private IDF header.
#define ETH_SPI_DMA_ALIGN (64)
// Ethernet frame is at most 1518 bytes, 1522 with a VLAN tag. 1600 is the next multiple
// of the alignment above it and leaves room to spare.
#define ETH_SPI_DMA_BUF_SIZE (1600)

#define ETH_SPI_LOCK_TIMEOUT_MS (50)

typedef struct
{
    spi_device_handle_t hdl;
    SemaphoreHandle_t lock;
    uint8_t *dma_buf;
} eth_spi_dma_ctx_t;

void *eth_spi_dma_init(const void *spi_config)
{
    const eth_spi_dma_config_t *cfg = (const eth_spi_dma_config_t *)spi_config;
    if (cfg == NULL || cfg->spi_devcfg == NULL)
    {
        ESP_LOGE(TAG, "no SPI configuration");
        return NULL;
    }

    eth_spi_dma_ctx_t *ctx = calloc(1, sizeof(eth_spi_dma_ctx_t));
    if (ctx == NULL)
    {
        ESP_LOGE(TAG, "no memory for SPI context");
        return NULL;
    }

    // Same default frame format the stock driver applies: 16 address bits and 8 control
    // bits, which the W5500 uses as its address and command phases respectively.
    spi_device_interface_config_t devcfg = *cfg->spi_devcfg;
    if (devcfg.command_bits == 0 && devcfg.address_bits == 0)
    {
        devcfg.command_bits = 16;
        devcfg.address_bits = 8;
    }
    else if (devcfg.command_bits != 16 || devcfg.address_bits != 8)
    {
        ESP_LOGE(TAG, "incorrect SPI frame format (command_bits/address_bits)");
        goto err;
    }

    if (spi_bus_add_device(cfg->spi_host_id, &devcfg, &ctx->hdl) != ESP_OK)
    {
        ESP_LOGE(TAG, "adding device to SPI host #%i failed", cfg->spi_host_id + 1);
        goto err;
    }

    ctx->lock = xSemaphoreCreateMutex();
    if (ctx->lock == NULL)
    {
        ESP_LOGE(TAG, "create lock failed");
        goto err;
    }

    ctx->dma_buf = heap_caps_aligned_alloc(ETH_SPI_DMA_ALIGN, ETH_SPI_DMA_BUF_SIZE,
                                           MALLOC_CAP_DMA | MALLOC_CAP_INTERNAL);
    if (ctx->dma_buf == NULL)
    {
        ESP_LOGE(TAG, "no DMA-capable memory for the %d byte TX buffer", ETH_SPI_DMA_BUF_SIZE);
        goto err;
    }

    ESP_LOGI(TAG, "W5500 TX buffer %d bytes at %p, alignment %d - frame writes allocate nothing",
             ETH_SPI_DMA_BUF_SIZE, ctx->dma_buf, ETH_SPI_DMA_ALIGN);
    return ctx;

err:
    if (ctx->dma_buf != NULL)
        heap_caps_free(ctx->dma_buf);
    if (ctx->lock != NULL)
        vSemaphoreDelete(ctx->lock);
    if (ctx->hdl != NULL)
        spi_bus_remove_device(ctx->hdl);
    free(ctx);
    return NULL;
}

esp_err_t eth_spi_dma_deinit(void *spi_ctx)
{
    eth_spi_dma_ctx_t *ctx = (eth_spi_dma_ctx_t *)spi_ctx;

    spi_bus_remove_device(ctx->hdl);
    vSemaphoreDelete(ctx->lock);
    heap_caps_free(ctx->dma_buf);
    free(ctx);
    return ESP_OK;
}

esp_err_t eth_spi_dma_write(void *spi_ctx, uint32_t cmd, uint32_t addr, const void *value, uint32_t len)
{
    eth_spi_dma_ctx_t *ctx = (eth_spi_dma_ctx_t *)spi_ctx;
    esp_err_t ret = ESP_OK;

    // cmd carries the 16-bit offset within the block, addr the block select bits.
    const uint32_t bsb = (addr >> W5500_BSB_OFFSET) & 0x1F;
    const bool to_socket_tx = (bsb == W5500_BSB_SOCK_TX_BUF(0));

    if (xSemaphoreTake(ctx->lock, pdMS_TO_TICKS(ETH_SPI_LOCK_TIMEOUT_MS)) != pdTRUE)
        return ESP_ERR_TIMEOUT;

    const void *tx_buffer = value;
    uint32_t tx_len = len;

    if (to_socket_tx && len <= ETH_SPI_DMA_BUF_SIZE)
    {
        memcpy(ctx->dma_buf, value, len);
        tx_buffer = ctx->dma_buf;

        // Round the transfer up so the length meets the bus alignment too. Safe only
        // here: the caller advances the socket's TX write pointer by the true frame
        // length straight after this call, so the chip transmits len bytes and the
        // padding is scratch in the ring. Skip it if the padding would run off the end
        // of the ring, where the address would wrap onto a frame not yet sent.
        const uint32_t padded = (len + ETH_SPI_DMA_ALIGN - 1) & ~(uint32_t)(ETH_SPI_DMA_ALIGN - 1);
        if (padded <= ETH_SPI_DMA_BUF_SIZE && (cmd + padded) <= W5500_TX_MEM_SIZE)
        {
            memset(ctx->dma_buf + len, 0, padded - len);
            tx_len = padded;
        }
    }

    spi_transaction_t trans = {
        .cmd = cmd,
        .addr = addr,
        .length = 8 * tx_len,
        .tx_buffer = tx_buffer,
    };
    if (spi_device_polling_transmit(ctx->hdl, &trans) != ESP_OK)
    {
        ESP_LOGE(TAG, "spi transmit failed");
        ret = ESP_FAIL;
    }

    xSemaphoreGive(ctx->lock);
    return ret;
}

esp_err_t eth_spi_dma_read(void *spi_ctx, uint32_t cmd, uint32_t addr, void *value, uint32_t len)
{
    eth_spi_dma_ctx_t *ctx = (eth_spi_dma_ctx_t *)spi_ctx;
    esp_err_t ret = ESP_OK;

    spi_transaction_t trans = {
        // Direct reads for register-sized transfers, so a 4-byte boundary write cannot
        // overwrite them - same reasoning as the stock driver.
        .flags = len <= 4 ? SPI_TRANS_USE_RXDATA : 0,
        .cmd = cmd,
        .addr = addr,
        .length = 8 * len,
        .rx_buffer = value,
    };

    if (xSemaphoreTake(ctx->lock, pdMS_TO_TICKS(ETH_SPI_LOCK_TIMEOUT_MS)) != pdTRUE)
        return ESP_ERR_TIMEOUT;

    if (spi_device_polling_transmit(ctx->hdl, &trans) != ESP_OK)
    {
        ESP_LOGE(TAG, "spi transmit failed");
        ret = ESP_FAIL;
    }

    xSemaphoreGive(ctx->lock);

    if ((trans.flags & SPI_TRANS_USE_RXDATA) && len <= 4)
        memcpy(value, trans.rx_data, len);

    return ret;
}
