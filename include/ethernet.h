#include <esp_err.h>
#include <esp_netif_types.h>

#ifdef __cplusplus
extern "C"
{
#endif

bool ethernet_set_config(char *json, bool *save);
esp_err_t ethernet_init(char*json);
esp_err_t ethernet_connect(void);
esp_err_t ethernet_disconnect(void);
esp_netif_t* ethernet_get_netif();
const char* ethernet_get_hostname();
bool ethernet_valid_ip(const char *ip);

#ifdef __cplusplus
}
#endif
