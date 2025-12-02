#include <esp_err.h>
#include <esp_netif_types.h>

#define MAX_HOSTNAME 32
#define MAX_IP 20
#define MAX_SSID 32
#define MAX_PW 64
#define MAX_SNTP_NAME 32

#ifdef __cplusplus
extern "C"
{
#endif
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
            struct
            {
                int reset;
                int miso;
                int mosi;
                int sclk;
                int cs;
                int irq;
            } gpio;
        } phy;

    } ethernet_settings_t;

    /// @brief Initialize the ethernet module
    /// @deprecated Use ethernet_config instead
    /// @param json The JSON string containing the configuration
    /// @param save If true, the configuration will be saved to NVS
    /// @return True on success, false on failure
    bool ethernet_init(const char *json, bool *save);

    /// @brief Configure the ethernet module
    /// @param settings The settings to use
    /// @return True on success, false on failure
    bool ethernet_config(const ethernet_settings_t *settings);

    /// @brief Start the ethernet module
    void ethernet_start();

    /// @brief Start the ethernet module in AP mode. Overrides
    /// the settings in the configuration.
    void ethernet_start_ap();

    /// @brief Start the ethernet module in STA mode. Overrides
    /// the settings in the configuration.
    void ethernet_start_phy();

    /// @brief Stop the ethernet module
    void ethernet_stop();

    bool ethernet_got_eth_link();

    /// @brief Check if the ethernet module has got an IP address
    /// @return True if an IP address has been obtained, false otherwise
    bool ethernet_got_ip();

    /// @brief Get the hostname
    /// @return The hostname
    const char *ethernet_get_hostname();

    /// @brief Get the IP address
    /// @return The current IP address
    const char *ethernet_get_ip();

    /// @brief Check if an IP address is valid
    /// @param ip The address to check
    /// @return True if the address is valid, false otherwise
    bool ethernet_valid_ip(const char *ip);

    /// @brief Get the RSSI of the WiFi connection
    /// @return The RSSI in % or 0 if not connected
    float wifi_get_rssi();

#ifdef __cplusplus
}
#endif
