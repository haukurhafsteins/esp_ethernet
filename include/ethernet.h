#include <esp_err.h>
#include <esp_netif_types.h>

#ifdef __cplusplus
extern "C"
{
#endif

bool ethernet_init(const char *json, bool* save);
esp_err_t ethernet_start();
bool ethernet_stop();
bool ethernet_got_ip();
esp_netif_t* ethernet_get_netif();
const char* ethernet_get_hostname();
const char* ethernet_get_ip();
bool ethernet_valid_ip(const char *ip);

#ifdef __cplusplus
}
#endif
