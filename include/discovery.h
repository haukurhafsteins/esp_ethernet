#pragma once
#include "mdns.h"
#ifdef __cplusplus
extern "C"
{
#endif
bool discovery_start();
bool discovery_init(const char *json, bool *save);
mdns_result_t *discovery_find_mdns_service(const char *type, const char *proto);
#ifdef __cplusplus
}
#endif
