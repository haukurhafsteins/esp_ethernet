#include <esp_err.h>
#include <esp_netif_types.h>

#ifdef __cplusplus
extern "C"
{
#endif

bool ethernet_stop();
esp_err_t ethernet_start(const char*json);
esp_netif_t* ethernet_get_netif();
const char* ethernet_get_hostname();
bool ethernet_valid_ip(const char *ip);

#ifdef __cplusplus
}
#endif
