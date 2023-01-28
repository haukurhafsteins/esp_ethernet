
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "esp_eth.h"
#include "esp_event.h"
#include "esp_log.h"
#include "driver/gpio.h"
#include "sdkconfig.h"
// #include "nvsstorage.h"
#include "cjson.h"
#include "cjson_utils.h"

#define MAX_HOSTNAME 128
#define MAX_IP 20

#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT BIT1

static const char *TAG = "ETHERNET";
static esp_netif_t *eth_netif;
static char hostname[MAX_HOSTNAME] = "parkinsonglove";
static bool dhcp = true;
static bool cfg_wifi = true;
static int cfg_max_connect_retry = 10;
static int cfg_auth_mode = WIFI_AUTH_WPA2_PSK; //WIFI_AUTH_WEP;
static char ip[MAX_IP] = "";
static char netmask[MAX_IP] = "";
static char gateway[MAX_IP] = "";
static int32_t cfg_phy_addr = 1;
static int cfg_reset_gpio_num = 5;
static int cfg_smi_mdc_gpio_num = 23;
static int cfg_smi_mdio_gpio_num = 18;
static int connect_retry_counter = 0;
static EventGroupHandle_t s_wifi_event_group;

static void wifi_event_handler(void *arg, esp_event_base_t event_base,
                               int32_t event_id, void *event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START)
    {
        esp_wifi_connect();
    }
    else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED)
    {
        if (connect_retry_counter < cfg_max_connect_retry)
        {
            esp_wifi_connect();
            connect_retry_counter++;
            ESP_LOGI(TAG, "retry to connect to the AP");
        }
        else
        {
            xEventGroupSetBits(s_wifi_event_group, WIFI_FAIL_BIT);
        }
        ESP_LOGI(TAG, "connect to the AP fail");
    }
    else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP)
    {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
        ESP_LOGI(TAG, "got ip:" IPSTR, IP2STR(&event->ip_info.ip));
        connect_retry_counter = 0;
        xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

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

esp_netif_t *ethernet_get_netif()
{
    return eth_netif;
}
const char *ethernet_get_hostname()
{
    const char *p;
    esp_netif_get_hostname(eth_netif, &p);
    return p;
}

static const char *ethernet_get_default_hostname()
{
    static char default_hostname[64];
    int64_t num = 0x1463785698109456;
    esp_efuse_mac_get_default((uint8_t *)&num);
    snprintf(default_hostname, 64, "masi-%lld", num / 3);
    return default_hostname;
}

static bool ethernet_configure(const char *json)
{
    cJSON *doc = cJSON_Parse(json);
    if (doc == NULL)
        return false;

    cJSON *eth = cJSON_GetObjectItemCaseSensitive(doc, "ethernetSettings");
    cJSON_GetString(eth, "hostname", "", hostname, MAX_HOSTNAME);
    cJSON_GetString(eth, "ip", ip, ip, MAX_IP);
    cJSON_GetString(eth, "netmask", netmask, netmask, MAX_IP);
    cJSON_GetString(eth, "gateway", gateway, gateway, MAX_IP);
    dhcp = cJSON_GetBool(eth, "dhcp", dhcp);
    cfg_wifi = cJSON_GetBool(eth, "wifi", cfg_wifi);

    cJSON_Delete(doc);
    return true;
}

bool ethernet_valid_ip(const char *ip)
{
    struct in_addr in;
    return inet_aton(ip, &in) != 0;
}

void ethernet_start(const char *json)
{
    ethernet_configure(json);

    if (hostname[0] == '\0')
        snprintf(hostname, MAX_HOSTNAME, "%s", ethernet_get_default_hostname());

    ESP_ERROR_CHECK(esp_netif_init());

    esp_event_handler_instance_t instance_got_ip;

    if (cfg_wifi)
    {
        wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
        ESP_ERROR_CHECK(esp_wifi_init(&cfg));
        esp_event_handler_instance_t instance_any_id;
        ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, &instance_any_id));
        ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL, &instance_got_ip));
        wifi_config_t wifi_config = {
            .sta = {
                .ssid = "MP9",
                .password = "Mp9HTIDev",
                /* Setting a password implies station will connect to all security modes including WEP/WPA.
                 * However these modes are deprecated and not advisable to be used. Incase your Access point
                 * doesn't support WPA2, these mode can be enabled by commenting below line */
                .threshold.authmode = cfg_auth_mode,
            },
        };
        ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
        ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
        tcpip_adapter_set_hostname(TCPIP_ADAPTER_IF_STA, hostname);
        ESP_ERROR_CHECK(esp_wifi_start());
    }
    else
    {
        esp_netif_config_t cfg = ESP_NETIF_DEFAULT_ETH();
        esp_netif_ip_info_t ip_info;
        eth_netif = esp_netif_new(&cfg);

        // ESP_ERROR_CHECK(esp_eth_set_default_handlers(eth_netif));
        ESP_ERROR_CHECK(esp_event_handler_register(ETH_EVENT, ESP_EVENT_ANY_ID, &eth_event_handler, NULL));
        ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &got_ip_event_handler, NULL, &instance_got_ip));

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
        phy_config.phy_addr = cfg_phy_addr;
        phy_config.reset_gpio_num = cfg_reset_gpio_num;
        mac_config.sw_reset_timeout_ms = 1000;
        mac_config.smi_mdc_gpio_num = cfg_smi_mdc_gpio_num;
        mac_config.smi_mdio_gpio_num = cfg_smi_mdio_gpio_num;

        esp_eth_mac_t *mac = esp_eth_mac_new_esp32(&mac_config);
        esp_eth_phy_t *phy = esp_eth_phy_new_lan87xx(&phy_config);

        esp_eth_config_t config = ETH_DEFAULT_CONFIG(mac, phy);
        esp_eth_handle_t eth_handle = NULL;
        ESP_ERROR_CHECK(esp_eth_driver_install(&config, &eth_handle));
        /* attach Ethernet driver to TCP/IP stack */
        ESP_ERROR_CHECK(esp_netif_attach(eth_netif, esp_eth_new_netif_glue(eth_handle)));
        ESP_ERROR_CHECK(esp_netif_set_hostname(eth_netif, hostname));
        ESP_ERROR_CHECK(esp_eth_start(eth_handle));
    }
    ESP_LOGI(TAG, "Hostname: %s", hostname);
}

void ethernet_stop()
{
}