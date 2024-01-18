
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "esp_eth.h"
#include "esp_mac.h"
#include "esp_event.h"
#include "esp_log.h"
#include "driver/gpio.h"
#include "sdkconfig.h"
// #include "nvsstorage.h"
#include "cJSON.h"
#include "cJSON_Params.h"

#define MAX_HOSTNAME 32
#define MAX_IP 20
#define MAX_SSID 32
#define MAX_PW 64

#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT BIT1

typedef enum
{
    network_type_ap = 0,
    network_type_sta,
    network_type_phy,
    network_type_end
} network_type_t;

typedef struct
{
    char hostname[MAX_HOSTNAME];
    network_type_t type;
    struct
    {
        char ip[MAX_IP];
        char netmask[MAX_IP];
        char gateway[MAX_IP];
        char ssid[MAX_SSID];
        char password[MAX_PW];
        bool dhcp;
    } wifi;
    struct
    {
        int channel;
        char password[MAX_PW];
    } ap;
} ethernet_settings_t;

static const char *TAG = "ETHERNET";
static esp_netif_t *eth_netif;
static ethernet_settings_t ethernet_settings = {
    .hostname = "AsgardGrip",
    .type = network_type_ap,
    .wifi = {
        .ip = "",
        .netmask = "",
        .gateway = "",
        .ssid = "",
        .password = "",
        .dhcp = true},
    .ap = {.channel = 2, .password = ""}};
static esp_event_handler_instance_t instance_got_ip;
static esp_event_handler_instance_t instance_any_id;
static int connect_retry_counter = 0;
static const int max_connect_retry = 10;
static bool initialized = false;

static void wifi_deinit_sta();
static void wifi_init_softap();

static void wifi_event_handler(void *arg, esp_event_base_t event_base,
                               int32_t event_id, void *event_data)
{
    if (event_base == WIFI_EVENT)
    {
        wifi_event_ap_staconnected_t *event_connected;
        wifi_event_ap_stadisconnected_t *event_disconnected;
        switch (event_id)
        {
        case WIFI_EVENT_STA_START:
            esp_wifi_connect();
            ESP_LOGI(TAG, "WIFI_EVENT_STA_START");
            break;
        case WIFI_EVENT_STA_STOP:
            ESP_LOGI(TAG, "WIFI_EVENT_STA_STOP");
            break;
        case WIFI_EVENT_STA_CONNECTED:
            ESP_LOGI(TAG, "WIFI_EVENT_STA_CONNECTED");
            break;
        case WIFI_EVENT_STA_DISCONNECTED:
            connect_retry_counter++;
            if (connect_retry_counter >= max_connect_retry)
            {
                wifi_deinit_sta();
                wifi_init_softap();
            }
            else
                esp_wifi_connect();
            ESP_LOGI(TAG, "WIFI_EVENT_STA_DISCONNECTED");
            break;

        case WIFI_EVENT_AP_STOP:
            ESP_LOGI(TAG, "WIFI_EVENT_AP_STOP");
            break;
        case WIFI_EVENT_AP_START:
            ESP_LOGI(TAG, "WIFI_EVENT_AP_START");
            break;
        case WIFI_EVENT_AP_STACONNECTED:
            event_connected = (wifi_event_ap_staconnected_t *)event_data;
            ESP_LOGI(TAG, "WIFI_EVENT_AP_STACONNECTED: station " MACSTR " join, AID=%d",
                     MAC2STR(event_connected->mac), event_connected->aid);
            break;
        case WIFI_EVENT_AP_STADISCONNECTED:
            event_disconnected = (wifi_event_ap_stadisconnected_t *)event_data;
            ESP_LOGI(TAG, "WIFI_EVENT_AP_STADISCONNECTED: station " MACSTR " leave, AID=%d",
                     MAC2STR(event_disconnected->mac), event_disconnected->aid);
            break;
        default:
            ESP_LOGW(TAG, "Unhandled event_id, Base: WIFI_EVENT, id: %lu", event_id);
            break;
        }
    }
    else if (event_base == IP_EVENT)
    {
        ip_event_got_ip_t *event;
        switch (event_id)
        {
        case IP_EVENT_STA_GOT_IP:
            event = (ip_event_got_ip_t *)event_data;
            const esp_netif_ip_info_t *ip_info = &event->ip_info;
            ESP_LOGI(TAG, "IP_EVENT_STA_GOT_IP");
            ESP_LOGI(TAG, "~~~~~~~~~~~");
            ESP_LOGI(TAG, "ETH IP  :" IPSTR, IP2STR(&ip_info->ip));
            ESP_LOGI(TAG, "ETH MASK:" IPSTR, IP2STR(&ip_info->netmask));
            ESP_LOGI(TAG, "ETH GW  :" IPSTR, IP2STR(&ip_info->gw));
            ESP_LOGI(TAG, "~~~~~~~~~~~");
            break;
        default:
            ESP_LOGW(TAG, "Unhandled event_id Base: IP_EVENT, id: %lu", event_id);
            break;
        }
    }
    else if (event_base == ETH_EVENT)
    {
        uint8_t mac_addr[6] = {0};
        // we can get the ethernet driver handle from event data
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
    else
    {
        ESP_LOGW(TAG, "Unhandled network event - Base: %s, id: %lu", event_base, event_id);
    }
}

esp_netif_t *ethernet_get_netif()
{
    return eth_netif;
}
const char *ethernet_get_ip()
{
    const esp_netif_ip_info_t ip_info;
    if (ESP_OK == esp_netif_get_ip_info(eth_netif, &ip_info))
        return ip4addr_ntoa(&ip_info.ip);
    return "";
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
    snprintf(default_hostname, 64, "%s-%lld", CONFIG_E_NET_DEFAULT_HOSTNAME, num / 3);
    return default_hostname;
}

static bool ethernet_valid_hostname(const char *hostname)
{
    return strlen(hostname) > 0 && strlen(hostname) < MAX_HOSTNAME;
}

bool ethernet_valid_ip(const char *ip)
{
    struct in_addr in;
    return inet_aton(ip, &in) != 0;
}

void wifi_init_softap(void)
{
    eth_netif = esp_netif_create_default_wifi_ap();
    assert(eth_netif);

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, NULL));

    // Set the IP address for the SoftAP interface
    esp_netif_ip_info_t ip_info = {};
    IP4_ADDR(&ip_info.ip, 192, 168, 4, 1);        // Set the desired IP address (e.g., 192.168.4.1)
    IP4_ADDR(&ip_info.gw, 192, 168, 4, 1);        // Set the gateway IP address (same as the SoftAP IP)
    IP4_ADDR(&ip_info.netmask, 255, 255, 255, 0); // Set the subnet mask (e.g., 255.255.255.0)

    ESP_ERROR_CHECK(esp_netif_dhcps_stop(eth_netif));
    ESP_ERROR_CHECK(esp_netif_set_ip_info(eth_netif, &ip_info));

    // Start the DHCP server for the SoftAP
    ESP_ERROR_CHECK(esp_netif_dhcps_start(eth_netif));

    wifi_config_t wifi_config = {
        .ap = {
            .channel = ethernet_settings.ap.channel,
            .max_connection = 2,
            //.authmode = WIFI_AUTH_WPA2_WPA3_PSK,
            .authmode = WIFI_AUTH_OPEN,
            //.authmode = WIFI_AUTH_WPA2_PSK,
            .sae_pwe_h2e = WPA3_SAE_PWE_BOTH,
            .pmf_cfg = {.required = true}}};

    wifi_config.ap.ssid_len = strlen(ethernet_settings.hostname);
    snprintf((char *)wifi_config.ap.ssid, MAX_SSID, "%s", ethernet_settings.hostname);
    // if (strlen(cfg_password) == 0)
    //{
    // wifi_config.ap.sae_pwe_h2e = WPA3_SAE_PWE_UNSPECIFIED;
    ESP_LOGW(TAG, "No password: OPEN NETWORK!");
    //}
    // else
    //{
    //    snprintf((char *)wifi_config.ap.password, MAX_PW, "%s", cfg_password);
    //}

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "AP init finished. SSID:%s password:%s channel:%d",
             ethernet_settings.hostname, ethernet_settings.ap.password, ethernet_settings.ap.channel);
}

static void wifi_deinit_softap()
{
    ESP_ERROR_CHECK(esp_wifi_stop());
    ESP_ERROR_CHECK(esp_netif_dhcps_stop(eth_netif));
    esp_netif_destroy_default_wifi(eth_netif);
    ESP_ERROR_CHECK(esp_wifi_deinit());
    esp_event_handler_instance_unregister(WIFI_EVENT, ESP_EVENT_ANY_ID, NULL);
}

static void wifi_init_sta()
{
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, &instance_any_id));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL, &instance_got_ip));
    eth_netif = esp_netif_create_default_wifi_sta();
    assert(eth_netif);
    wifi_config_t wifi_config = {
        .sta = {
            .scan_method = WIFI_ALL_CHANNEL_SCAN,
            .threshold.rssi = -127,
            .threshold.authmode = WIFI_AUTH_OPEN,
            /* Setting a password implies station will connect to all security modes including WEP/WPA.
             * However these modes are deprecated and not advisable to be used. Incase your Access point
             * doesn't support WPA2, these mode can be enabled by commenting below line */
            //.threshold.authmode = cfg_auth_mode,
        },
    };
    snprintf((char *)wifi_config.sta.ssid, MAX_SSID, "%s", ethernet_settings.wifi.ssid);
    snprintf((char *)wifi_config.sta.password, MAX_PW, "%s", ethernet_settings.wifi.password);

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    esp_netif_set_hostname(eth_netif, ethernet_settings.hostname);
    ESP_ERROR_CHECK(esp_wifi_start());
}

static void wifi_deinit_sta()
{
    ESP_ERROR_CHECK(esp_wifi_stop());
    esp_netif_destroy_default_wifi(eth_netif);
    ESP_ERROR_CHECK(esp_wifi_deinit());
    ESP_ERROR_CHECK(esp_event_handler_instance_unregister(IP_EVENT, IP_EVENT_STA_GOT_IP, instance_got_ip));
    ESP_ERROR_CHECK(esp_event_handler_instance_unregister(WIFI_EVENT, ESP_EVENT_ANY_ID, instance_any_id));
}

static void phy_init()
{
    //  Create instance(s) of esp-netif for SPI Ethernet(s)
    esp_netif_inherent_config_t esp_netif_config = ESP_NETIF_INHERENT_DEFAULT_ETH();
    esp_netif_config_t cfg_spi = {
        .base = &esp_netif_config,
        .stack = ESP_NETIF_NETSTACK_DEFAULT_ETH
    };
    char if_key_str[10];
    char if_desc_str[10];
    char num_str[3];
    itoa(0, num_str, 10);
    strcat(strcpy(if_key_str, "ETH_SPI_"), num_str);
    strcat(strcpy(if_desc_str, "eth"), num_str);
    esp_netif_config.if_key = if_key_str;
    esp_netif_config.if_desc = if_desc_str;
    esp_netif_config.route_prio = 30;
    eth_netif = esp_netif_new(&cfg_spi);

    eth_mac_config_t mac_config = ETH_MAC_DEFAULT_CONFIG(); // apply default common MAC configuration
    eth_phy_config_t phy_config = ETH_PHY_DEFAULT_CONFIG(); // apply default PHY configuration
    phy_config.phy_addr = 0;                                // alter the PHY address according to your board design
    phy_config.reset_gpio_num = GPIO_NUM_39;                // alter the GPIO used for PHY reset
    spi_bus_config_t buscfg = {
        .miso_io_num = GPIO_NUM_38,
        .mosi_io_num = GPIO_NUM_36,
        .sclk_io_num = GPIO_NUM_37,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
    };
    ESP_ERROR_CHECK(spi_bus_initialize(SPI3_HOST, &buscfg, SPI_DMA_CH_AUTO));
    spi_device_interface_config_t spi_devcfg = {
        .mode = 0,
        .clock_speed_hz = 20 * 1000 * 1000,
        .spics_io_num = GPIO_NUM_35,
        .queue_size = 20};
    eth_w5500_config_t w5500_config = ETH_W5500_DEFAULT_CONFIG(SPI3_HOST, &spi_devcfg);
    w5500_config.int_gpio_num = GPIO_NUM_40;
    esp_eth_mac_t *mac_spi = esp_eth_mac_new_w5500(&w5500_config, &mac_config);
    esp_eth_phy_t *phy_spi = esp_eth_phy_new_w5500(&phy_config);

    esp_eth_config_t eth_config_spi = ETH_DEFAULT_CONFIG(mac_spi, phy_spi);
    esp_eth_handle_t eth_handle = NULL;
    ESP_ERROR_CHECK(esp_eth_driver_install(&eth_config_spi, &eth_handle));

    uint8_t mac_addr[6];
    esp_read_mac(mac_addr, ESP_MAC_ETH);
    ESP_ERROR_CHECK(esp_eth_ioctl(eth_handle, ETH_CMD_S_MAC_ADDR, mac_addr));
    ESP_ERROR_CHECK(esp_netif_attach(eth_netif, esp_eth_new_netif_glue(eth_handle)));

    esp_event_handler_instance_register(ETH_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, &instance_any_id);
    esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL, &instance_got_ip);

    esp_netif_set_hostname(eth_netif, ethernet_settings.hostname);

    esp_eth_start(eth_handle);
}

static void start(network_type_t type)
{
    switch (type)
    {
    case network_type_phy:
        phy_init();
        break;
    case network_type_ap:
        wifi_init_softap();
        break;
    case network_type_sta:
    default:
        wifi_init_sta();
        break;
    }
}

static void stop(network_type_t type)
{
    switch (type)
    {
    case network_type_phy:
        //phy_deinit();
        break;
    case network_type_ap:
        wifi_deinit_softap();
        break;
    case network_type_sta:
    default:
        wifi_deinit_sta();
        break;
    }
}

bool ethernet_init(const char *json, bool *save)
{
    // Default hostname must be set to unique value. Will be overwritten by settings.
    snprintf(ethernet_settings.hostname, MAX_HOSTNAME, "%s", ethernet_get_default_hostname());

    cJSON *doc = cJSON_Parse(json);
    if (doc == NULL)
        return false;

    if (save != NULL)
        *save = true;

    cJSON_GetString(doc, "hostname", "", ethernet_settings.hostname, MAX_HOSTNAME);
    network_type_t prevType = ethernet_settings.type;
    ethernet_settings.type = cJSON_GetInt(doc, "type", ethernet_settings.type, network_type_ap, network_type_end - 1);

    cJSON *wifi = cJSON_GetObjectItemCaseSensitive(doc, "wifi");
    cJSON_GetString(wifi, "ip", ethernet_settings.wifi.ip, ethernet_settings.wifi.ip, MAX_IP);
    cJSON_GetString(wifi, "netmask", ethernet_settings.wifi.netmask, ethernet_settings.wifi.netmask, MAX_IP);
    cJSON_GetString(wifi, "gateway", ethernet_settings.wifi.gateway, ethernet_settings.wifi.gateway, MAX_IP);
    cJSON_GetString(wifi, "ssid", ethernet_settings.wifi.ssid, ethernet_settings.wifi.ssid, MAX_SSID);
    cJSON_GetString(wifi, "password", ethernet_settings.wifi.password, ethernet_settings.wifi.password, MAX_PW);
    ethernet_settings.wifi.dhcp = cJSON_GetBool(wifi, "dhcp", ethernet_settings.wifi.dhcp);

    cJSON *ap = cJSON_GetObjectItemCaseSensitive(doc, "ap");
    ethernet_settings.ap.channel = cJSON_GetInt(ap, "channel", (int)ethernet_settings.ap.channel, 1, 13);
    cJSON_GetString(ap, "password", ethernet_settings.ap.password, ethernet_settings.ap.password, MAX_PW);

    cJSON_Delete(doc);

    if (!ethernet_valid_hostname(ethernet_settings.hostname))
        snprintf(ethernet_settings.hostname, MAX_HOSTNAME, "%s", ethernet_get_default_hostname());

    if (ethernet_settings.type == network_type_sta && ethernet_settings.wifi.ssid[0] == '\0')
    {
        ESP_LOGW(TAG, "No SSID set. Starting AP mode.");
        ethernet_settings.type = network_type_ap;
    }

    if (initialized && ethernet_settings.type != prevType)
    {
        ESP_LOGI(TAG, "Network type changed. Restarting network.");
        stop(prevType);
    start(ethernet_settings.type);
    }

    return true;
}

void ethernet_start()
{
    ESP_ERROR_CHECK(esp_netif_init());

    start(ethernet_settings.type);
    initialized = true;
}

void ethernet_stop()
{
stop(ethernet_settings.type);
}