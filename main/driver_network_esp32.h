#ifndef __DRIVER_NETWORK_ESP32_H__
#define __DRIVER_NETWORK_ESP32_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include "env.h"

#if defined(PLATFORM_ESP32)

#include "interface_wifi.h"

void esp_network_init(void);
int esp_network_connected(void);

int esp_network_tcp_server(uint16_t port);
int esp_network_tcp_accept(int fp, uint8_t *ip, uint16_t *port);
int esp_network_tcp_client(const char *host, uint16_t port);
int esp_network_tcp_connected(int fp);

int esp_network_tcp_recv(int fp, void *buffer, uint32_t size);
int esp_network_tcp_send(int fp, const void *buffer, uint32_t size);

int esp_network_udp_create(uint16_t port);
int esp_network_udp_recv(int fp, void *buffer, uint32_t size, uint8_t *ip, uint16_t *port);
int esp_network_udp_send(int fp, const void *buffer, uint32_t size, const uint8_t *ip, uint16_t port);

int esp_network_close(int fp);

int esp_network_ip(uint8_t *ip);
int esp_network_mask(uint8_t *mask);
int esp_network_nat(uint8_t *nat);
int esp_network_mac(uint8_t *mac);
int esp_network_dns_primary(uint8_t *dns);
int esp_network_dns_secondary(uint8_t *dns);

void esp_network_wifi_ap_connect(const char *ssid, const char *password, const uint8_t *bssid);
void esp_network_wifi_ap_disconnect(void);
int esp_network_wifi_sta_status(void);
int esp_network_wifi_ap_rssi(void);
void esp_network_wifi_scan_ap(const uint8_t *bssid, WifiAPListCallback cb);
void esp_network_wifi_sniffer_callback(WifiSnifferCallback cb);
void esp_network_wifi_sniffer_channel(uint8_t channel, int8_t modifier);
void esp_network_wifi_sniffer_start(void);
void esp_network_wifi_sniffer_stop(void);
void esp_network_wifi_sniffer_send(const uint8_t *frame, uint32_t size);

#endif

#ifdef __cplusplus
}
#endif

#endif
