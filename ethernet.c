
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_netif.h"
#include "esp_eth.h"
#include "esp_event.h"
#include "esp_log.h"
#include "driver/gpio.h"
#include "sdkconfig.h"
//#include "nvsstorage.h"
#include "cjson.h"
#include "cjson_utils.h"

#define MAX_HOSTNAME 128
#define MAX_IP 20

static const char *TAG = "ETHERNET";
static esp_netif_t *eth_netif;

static char hostname[MAX_HOSTNAME];
static bool dhcp = true;
static char ip[MAX_IP] = "";
static char netmask[MAX_IP] = "";
static char gateway[MAX_IP] = "";
static bool save_config = false;

/** Event handler for Ethernet events */
static void eth_event_handler(void *arg, esp_event_base_t event_base,
                              int32_t event_id, void *event_data)
{
    if (event_base == ETH_EVENT)
    {
        uint8_t mac_addr[6] = {0};
        /* we can get the ethernet driver handle from event data */
        esp_eth_handle_t eth_handle = *(esp_eth_handle_t *)event_data;

        switch (event_id)
        {
        case ETHERNET_EVENT_CONNECTED:
            esp_eth_ioctl(eth_handle, ETH_CMD_G_MAC_ADDR, mac_addr);
            ESP_LOGI(TAG, "Ethernet Link Up");
            ESP_LOGI(TAG, "Ethernet HW Addr %02x:%02x:%02x:%02x:%02x:%02x",
                     mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);
            break;
        case ETHERNET_EVENT_DISCONNECTED:
            ESP_LOGI(TAG, "Ethernet Link Down");
            break;
        case ETHERNET_EVENT_START:
            ESP_LOGI(TAG, "Ethernet Started");
            break;
        case ETHERNET_EVENT_STOP:
            ESP_LOGI(TAG, "Ethernet Stopped");
            break;
        default:
            break;
        }
    }
    else if (event_base == WIFI_EVENT)
    {
    }
    else if (event_base == IP_EVENT)
    {
    }
}

/** Event handler for IP_EVENT_ETH_GOT_IP */
static void got_ip_event_handler(void *arg, esp_event_base_t event_base,
                                 int32_t event_id, void *event_data)
{
    ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
    const esp_netif_ip_info_t *ip_info = &event->ip_info;

    ESP_LOGI(TAG, "Ethernet Got IP Address");
    ESP_LOGI(TAG, "~~~~~~~~~~~");
    ESP_LOGI(TAG, "ETH IP  :" IPSTR, IP2STR(&ip_info->ip));
    ESP_LOGI(TAG, "ETH MASK:" IPSTR, IP2STR(&ip_info->netmask));
    ESP_LOGI(TAG, "ETH GW  :" IPSTR, IP2STR(&ip_info->gw));
    ESP_LOGI(TAG, "~~~~~~~~~~~");
}

esp_netif_t* ethernet_get_netif() 
{
    return eth_netif;
}
const char* ethernet_get_hostname()
{
    const char *p;
    esp_netif_get_hostname(eth_netif, &p);
    return p;
}

static const char* ethernet_get_default_hostname()
{
    static char default_hostname[64];
    int64_t num = 0x1463785698109456;
    esp_efuse_mac_get_default((uint8_t*)&num);
    snprintf(default_hostname, 64, "masi-%lld", num/3);
    return default_hostname;
}

static bool ethernet_configure(const char *json, bool *save)
{
    cJSON *doc = cJSON_Parse(json);
    if (doc == NULL)
        return false;

    save_config = cJSON_GetBool(doc, "saveConfig", save_config);
    *save = save_config;

    cJSON *eth = cJSON_GetObjectItemCaseSensitive(doc, "ethernetSettings");
    cJSON_GetString(eth, "hostname", "", hostname, MAX_HOSTNAME);
    cJSON_GetString(eth, "ip", ip, ip, MAX_IP);
    cJSON_GetString(eth, "netmask", netmask, netmask, MAX_IP);
    cJSON_GetString(eth, "gateway", gateway, gateway, MAX_IP);
    dhcp = cJSON_GetBool(eth, "dhcp", dhcp);

    cJSON_Delete(doc);
    return true;
}

bool ethernet_valid_ip(const char *ip)
{
    struct in_addr in;
    return inet_aton(ip, &in) != 0;
}

void ethernet_start(char *json)
{
    bool save;
    ethernet_configure(json, &save);

    ESP_ERROR_CHECK(esp_netif_init()); 
    esp_netif_config_t cfg = ESP_NETIF_DEFAULT_ETH();
    esp_netif_ip_info_t ip_info;
    eth_netif = esp_netif_new(&cfg);

    //ESP_ERROR_CHECK(esp_eth_set_default_handlers(eth_netif));
    ESP_ERROR_CHECK(esp_event_handler_register(ETH_EVENT, ESP_EVENT_ANY_ID, &eth_event_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_ETH_GOT_IP, &got_ip_event_handler, NULL));

    if (!dhcp)
    {
        ESP_ERROR_CHECK(esp_netif_dhcpc_stop(eth_netif));
        ip_info.ip.addr = esp_ip4addr_aton(ip);
        ip_info.gw.addr = esp_ip4addr_aton(gateway);
        ip_info.netmask.addr = esp_ip4addr_aton(netmask);
        ESP_ERROR_CHECK(esp_netif_set_ip_info(eth_netif, &ip_info));
    }

    // Init MAC and PHY configs to default
    eth_mac_config_t mac_config = ETH_MAC_DEFAULT_CONFIG();
    eth_phy_config_t phy_config = ETH_PHY_DEFAULT_CONFIG();

    phy_config.reset_timeout_ms = 1000;
    phy_config.phy_addr = CONFIG_MFM_MASI_ETH_PHY_ADDR;
    phy_config.reset_gpio_num = CONFIG_MFM_MASI_ETH_PHY_RST_GPIO;
    mac_config.sw_reset_timeout_ms = 1000;
    mac_config.smi_mdc_gpio_num = CONFIG_MFM_MASI_ETH_MDC_GPIO;
    mac_config.smi_mdio_gpio_num = CONFIG_MFM_MASI_ETH_MDIO_GPIO;

    esp_eth_mac_t *mac = esp_eth_mac_new_esp32(&mac_config);
    esp_eth_phy_t *phy = esp_eth_phy_new_lan87xx(&phy_config);

    esp_eth_config_t config = ETH_DEFAULT_CONFIG(mac, phy);
    esp_eth_handle_t eth_handle = NULL;
    ESP_ERROR_CHECK(esp_eth_driver_install(&config, &eth_handle));
    /* attach Ethernet driver to TCP/IP stack */
    ESP_ERROR_CHECK(esp_netif_attach(eth_netif, esp_eth_new_netif_glue(eth_handle)));
    if (hostname[0] == '\0')
        snprintf(hostname, MAX_HOSTNAME, "%s", ethernet_get_default_hostname());
    ESP_LOGI(TAG, "Hostname: %s", hostname);
    ESP_ERROR_CHECK(esp_netif_set_hostname(eth_netif, hostname));
    ESP_ERROR_CHECK(esp_eth_start(eth_handle));
}

/*
void ethernet_init(void)
{
    // Initialize TCP/IP network interface (should be called only once in application)
    ESP_ERROR_CHECK(esp_netif_init());
    // Create new default instance of esp-netif for Ethernet
    esp_netif_config_t cfg = ESP_NETIF_DEFAULT_ETH();
    esp_netif_t *eth_netif = esp_netif_new(&cfg);

    // Init MAC and PHY configs to default
    eth_mac_config_t mac_config = ETH_MAC_DEFAULT_CONFIG();
    eth_phy_config_t phy_config = ETH_PHY_DEFAULT_CONFIG();

    phy_config.reset_timeout_ms = 1000;
    phy_config.phy_addr = CONFIG_MFM_MASI_ETH_PHY_ADDR;
    phy_config.reset_gpio_num = CONFIG_MFM_MASI_ETH_PHY_RST_GPIO;
    mac_config.sw_reset_timeout_ms = 1000;
    mac_config.smi_mdc_gpio_num = CONFIG_MFM_MASI_ETH_MDC_GPIO;
    mac_config.smi_mdio_gpio_num = CONFIG_MFM_MASI_ETH_MDIO_GPIO;

    esp_eth_mac_t *mac = esp_eth_mac_new_esp32(&mac_config);
    esp_eth_phy_t *phy = esp_eth_phy_new_lan87xx(&phy_config);
    esp_eth_config_t config = ETH_DEFAULT_CONFIG(mac, phy);
    esp_eth_handle_t eth_handle = NULL;
    ESP_ERROR_CHECK(esp_eth_driver_install(&config, &eth_handle));
    ESP_ERROR_CHECK(esp_netif_attach(eth_netif, esp_eth_new_netif_glue(eth_handle)));

    // Register user defined event handers
    ESP_ERROR_CHECK(esp_event_handler_register(ETH_EVENT, ESP_EVENT_ANY_ID, &eth_event_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_ETH_GOT_IP, &got_ip_event_handler, NULL));

    if (!dhcp_mode)
    {
        // have stop DHCP
        esp_netif_dhcpc_stop(eth_netif);

        esp_netif_ip_info_t ip_info;

        ip_info.ip.addr = esp_ip4addr_aton(CONFIG_MFM_MASI_STATIC_IP);
        ip_info.gw.addr = esp_ip4addr_aton(CONFIG_MFM_MASI_STATIC_GATEWAY);
        ip_info.netmask.addr = esp_ip4addr_aton(CONFIG_MFM_MASI_STATIC_NETMASK);

        ESP_ERROR_CHECK(esp_netif_set_ip_info(eth_netif, &ip_info));
    }

    esp_netif_set_hostname(eth_netif, "mfm-masi");

    ESP_ERROR_CHECK(esp_eth_start(eth_handle));
}

*/