
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

#define MAX_HOSTNAME 128
#define MAX_IP 20
#define MAX_SSID 32
#define MAX_PW 64

#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT BIT1

#define AP_WIFI_SSID "asgardgrip"
#define AP_WIFI_PASS "asgardgrip"

typedef enum
{
    netowork_type_ap,
    netowork_type_sta,
    netowork_type_phy
} network_type_t;

static const char *TAG = "ETHERNET";
static esp_netif_t *eth_netif;
static char cfg_hostname[32] = "AsgardGrip";
static bool cfg_dhcp = true;
static network_type_t cfg_network_type = netowork_type_ap;
static char cfg_ip[MAX_IP] = "";
static char cfg_netmask[MAX_IP] = "";
static char cfg_gateway[MAX_IP] = "";
static char cfg_ssid[MAX_SSID] = "";
static char cfg_password[MAX_PW] = "";
static int cfg_ap_channel = 2;
static esp_event_handler_instance_t instance_got_ip;
static esp_event_handler_instance_t instance_any_id;
static int connect_retry_counter = 0;
static int max_connect_retry = 10;

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

    // if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START)
    // {
    //     esp_wifi_connect();
    // }
    // else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED)
    // {
    //     esp_wifi_connect();
    // }
    // else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP)
    // {
    //     ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
    //     ESP_LOGI(TAG, "got ip:" IPSTR, IP2STR(&event->ip_info.ip));
    // }
    // else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_AP_STACONNECTED)
    // {
    //     wifi_event_ap_staconnected_t *event = (wifi_event_ap_staconnected_t *)event_data;
    //     ESP_LOGI(TAG, "station " MACSTR " join, AID=%d",
    //              MAC2STR(event->mac), event->aid);
    // }
    // else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_AP_STADISCONNECTED)
    // {
    //     wifi_event_ap_stadisconnected_t *event = (wifi_event_ap_stadisconnected_t *)event_data;
    //     ESP_LOGI(TAG, "station " MACSTR " leave, AID=%d",
    //              MAC2STR(event->mac), event->aid);
    // }
    // else
    // {
    //     // ESP_LOGI(TAG, "Network event - Base: %s, id: %lu", event_base, event_id);
    // }
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
    ESP_LOGI(TAG, "wifi_init_softap");
    eth_netif = esp_netif_create_default_wifi_ap();
    assert(eth_netif);

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT,
                                                        ESP_EVENT_ANY_ID,
                                                        &wifi_event_handler,
                                                        NULL,
                                                        NULL));

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
            .channel = cfg_ap_channel,
            .max_connection = 4,
#ifdef CONFIG_ESP_WIFI_SOFTAP_SAE_SUPPORT
            // .authmode = WIFI_AUTH_WPA2_WPA3_PSK,
            .authmode = WIFI_AUTH_OPEN,
            .sae_pwe_h2e = WPA3_SAE_PWE_BOTH,
#else /* CONFIG_ESP_WIFI_SOFTAP_SAE_SUPPORT */
            .authmode = WIFI_AUTH_WPA2_PSK,
#endif
            .pmf_cfg = {
                .required = true,
            },
        },
    };
    wifi_config.ap.ssid_len = strlen(cfg_hostname);
    snprintf((char *)wifi_config.ap.ssid, MAX_SSID, "%s", cfg_hostname);
    snprintf((char *)wifi_config.ap.password, MAX_PW, "%s", cfg_password);

    if (strlen(AP_WIFI_PASS) == 0)
    {
        wifi_config.ap.authmode = WIFI_AUTH_OPEN;
    }

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "wifi_init_softap finished. SSID:%s password:%s channel:%d",
             AP_WIFI_SSID, AP_WIFI_PASS, cfg_ap_channel);
}

static void wifi_deinit_softap()
{
    ESP_ERROR_CHECK(esp_wifi_stop());
    ESP_ERROR_CHECK(esp_netif_dhcps_stop(eth_netif));
    esp_netif_destroy_default_wifi(eth_netif);
    ESP_ERROR_CHECK(esp_wifi_deinit());
    ESP_ERROR_CHECK(esp_event_handler_instance_unregister(WIFI_EVENT, ESP_EVENT_ANY_ID, NULL));
}

static void wifi_init_sta()
{
    ESP_LOGI(TAG, "wifi_init_sta");

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
    snprintf((char *)wifi_config.sta.ssid, MAX_SSID, "%s", cfg_ssid);
    snprintf((char *)wifi_config.sta.password, MAX_PW, "%s", cfg_password);

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    esp_netif_set_hostname(eth_netif, cfg_hostname);
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
}

bool ethernet_init(const char *json, bool *save)
{
    cJSON *doc = cJSON_Parse(json);
    if (doc == NULL)
        return false;

    if (save != NULL)
        *save = true;

    cJSON *settings = cJSON_GetObjectItemCaseSensitive(doc, "ethernetSettings");
    cfg_network_type = cJSON_GetInt(settings, "type", (int)cfg_network_type, (int)netowork_type_ap, (int)netowork_type_phy);
    cfg_ap_channel = cJSON_GetInt(settings, "type", (int)cfg_ap_channel, 1, 11);
    cJSON_GetString(settings, "hostname", "", cfg_hostname, MAX_HOSTNAME);
    cJSON_GetString(settings, "ip", cfg_ip, cfg_ip, MAX_IP);
    cJSON_GetString(settings, "netmask", cfg_netmask, cfg_netmask, MAX_IP);
    cJSON_GetString(settings, "gateway", cfg_gateway, cfg_gateway, MAX_IP);
    cJSON_GetString(settings, "ssid", cfg_ssid, cfg_ssid, MAX_SSID);
    cJSON_GetString(settings, "password", cfg_password, cfg_password, MAX_PW);
    cfg_dhcp = cJSON_GetBool(settings, "dhcp", cfg_dhcp);

    cJSON_Delete(doc);

    if (!ethernet_valid_hostname(cfg_hostname))
        snprintf(cfg_hostname, MAX_HOSTNAME, "%s", ethernet_get_default_hostname());
    ESP_LOGI(TAG, "Hostname: %s", cfg_hostname);

    return true;
}

void ethernet_start()
{
    ESP_ERROR_CHECK(esp_netif_init());

    if (cfg_network_type == netowork_type_ap)
        wifi_init_softap();
    if (cfg_network_type == netowork_type_sta)
        wifi_init_sta();
    else
        phy_init();
}

void ethernet_stop()
{
}