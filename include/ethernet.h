#include <esp_err.h>
#include <esp_netif_types.h>

#ifdef __cplusplus
extern "C"
{
#endif

bool ethernet_init(const char *json, bool* save);
esp_err_t ethernet_start();
void ethernet_start_mdns_service();

bool ethernet_stop();
esp_netif_t* ethernet_get_netif();
const char* ethernet_get_hostname();
const char* ethernet_get_ip();
bool ethernet_valid_ip(const char *ip);

#ifdef __cplusplus
}
#endif
