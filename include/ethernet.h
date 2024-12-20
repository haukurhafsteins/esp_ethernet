#include <esp_err.h>
#include <esp_netif_types.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define MAX_HOSTNAME 32
#define MAX_IP 20
#define MAX_SSID 32
#define MAX_PW 64
#define MAX_SNTP_NAME 32

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
    char sntp[MAX_SNTP_NAME];
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
        int max_connections;
    } ap;
    struct
    {
        char ip[MAX_IP];
        char netmask[MAX_IP];
        char gateway[MAX_IP];
        char password[MAX_PW];
        bool dhcp;
        int reset_gpio_num;
        int miso_io_num;
        int mosi_io_num;
        int sclk_io_num;
        int spics_io_num;
        int int_gpio_num;
    } phy;

} ethernet_settings_t;

bool ethernet_init(const char *json, bool* save);
bool ethernet_initialize(ethernet_settings_t *settings);
void ethernet_start();
void ethernet_start_ap();
void ethernet_start_phy();
void ethernet_stop();
bool ethernet_got_ip();
esp_netif_t* ethernet_get_netif();
const char* ethernet_get_hostname();
const char* ethernet_get_ip();
bool ethernet_valid_ip(const char *ip);

float wifi_get_rssi();

#ifdef __cplusplus
}
#endif
