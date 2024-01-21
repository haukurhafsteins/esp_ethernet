#include <stdio.h>
#include <stdbool.h>
#include "esp_log.h"
#include "discovery.h"
#include "cJSON.h"
#include "cJSON_Params.h"
#include "ethernet.h"

#define MAX_INST_NAME 32
#define MAX_BOARD_NAME 32
#define MAX_SERVICE_TYPE 16
#define MAX_PROTO_TYPE 16

static const char TAG[] = "discovery";

typedef struct 
{
    char inst_name[MAX_INST_NAME];
    char board_name[MAX_BOARD_NAME];
    char service_type[MAX_SERVICE_TYPE];
    char proto_type[MAX_PROTO_TYPE];
} discovery_cfg_t;

static discovery_cfg_t discovery_cfg = {
    .inst_name = "ESP32",
};
static int query_timeout_ms = 1000;
static int query_max_results = 10;

mdns_result_t *discovery_find_mdns_service(const char *type, const char *proto)
{
    mdns_result_t *results = NULL;
    esp_err_t err = mdns_query_ptr(type, proto, query_timeout_ms, query_max_results, &results);
    if (err)
    {
        ESP_LOGE(TAG, "Query Failed");
        return NULL;
    }
    if (results == 0)
    {
        ESP_LOGW(TAG, "No results found!");
        return NULL;
    }
    return results;
}

bool discovery_init(const char *json, bool *save)
{
    cJSON *doc = cJSON_Parse(json);
    if (doc == NULL)
        return false;

    if (save != NULL)
        *save = true;

    cJSON_GetString(doc, "instName", discovery_cfg.inst_name, discovery_cfg.inst_name, MAX_INST_NAME);
    cJSON_GetString(doc, "boardName", discovery_cfg.board_name, discovery_cfg.board_name, MAX_INST_NAME);
    cJSON_GetString(doc, "serviceType", discovery_cfg.service_type, discovery_cfg.service_type, MAX_SERVICE_TYPE);
    cJSON_GetString(doc, "protoType", discovery_cfg.proto_type, discovery_cfg.proto_type, MAX_PROTO_TYPE);
    cJSON_Delete(doc);

    return true;
}

bool discovery_start()
{
    mdns_txt_item_t serviceTxtData[4] = {
        {"board", discovery_cfg.board_name},
        {"u", "user"},
        {"p", "password"},
        {"info", discovery_cfg.inst_name}};

    ESP_ERROR_CHECK(mdns_init());
    ESP_ERROR_CHECK(mdns_hostname_set(ethernet_get_hostname()));
    ESP_ERROR_CHECK(mdns_instance_name_set(discovery_cfg.inst_name));
    ESP_ERROR_CHECK(mdns_service_add(discovery_cfg.inst_name, discovery_cfg.service_type, discovery_cfg.proto_type, 80, serviceTxtData, 4));

    ESP_LOGI(TAG, "mdns started, hostname: %s, instance: %s, service type: %s, proto: %s", ethernet_get_hostname(), discovery_cfg.inst_name, discovery_cfg.service_type, discovery_cfg.proto_type);
    return true;
}