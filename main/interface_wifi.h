#ifndef __INTERFACE_WIFI_H__
#define __INTERFACE_WIFI_H__

enum {
    SIGMA_WIFI_STA_STATUS_DISCONNECTED = 0,
    SIGMA_WIFI_STA_STATUS_CONNECTING,
    SIGMA_WIFI_STA_STATUS_CONNECTED,
};

typedef struct
{
    const char *ssid;
    uint8_t *bssid;
    uint8_t channel;
    uint8_t security;
    int16_t rssi;
}WifiAPList;

typedef void (*WifiAPListCallback)(WifiAPList *list, int count);
typedef void (*WifiSnifferCallback)(const uint8_t *frame, uint16_t size);

#if defined(PLATFORM_ESP32)

#include "driver_network_esp32.h"

#define wifi_ap_connect esp_network_wifi_ap_connect
#define wifi_ap_disconnect esp_network_wifi_ap_disconnect
#define wifi_sta_status esp_network_wifi_sta_status
#define wifi_ap_rssi esp_network_wifi_ap_rssi
#define wifi_scan_ap esp_network_wifi_scan_ap
#define wifi_sniffer_callback esp_network_wifi_sniffer_callback
#define wifi_sniffer_channel esp_network_wifi_sniffer_channel
#define wifi_sniffer_start esp_network_wifi_sniffer_start
#define wifi_sniffer_stop esp_network_wifi_sniffer_stop
#define wifi_sniffer_send esp_network_wifi_sniffer_send

#elif defined(PLATFORM_LINUX)

#include "sigma_log.h"

#define wifi_ap_connect(ssid, password, bssid) SigmaLogAction(bssid, (bssid) ? 6 : 0, "ssid:%s password:%s bssid:", ssid, password)
#define wifi_ap_disconnect()
#define wifi_sta_status() SIGMA_WIFI_STA_STATUS_CONNECTED
#define wifi_ap_rssi 
#define wifi_scan_ap 
#define wifi_sniffer_callback(callback) SigmaLogAction(0, 0, "wifi sniffer(not impl) callback:%p", callback)
#define wifi_sniffer_channel(channel, modifier) //SigmaLogAction(0, 0, "wifi channel:%u modifier:%d", channel, modifier)
#define wifi_sniffer_start() SigmaLogAction(0, 0, "wifi sniffer(not impl) start.")
#define wifi_sniffer_stop() SigmaLogAction(0, 0, "wifi sniffer(not impl) stop")
#define wifi_sniffer_send(buffer, size) //SigmaLogAction(buffer, size, "wifi sniffer(not impl) send:")

#endif

#endif
