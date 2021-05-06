#ifndef __INTERFACE_NETWORK_H__
#define __INTERFACE_NETWORK_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include "env.h"
#include "endian.h"

#define NETWORK_MAC_LENGTH (6ul)

#define network_ntohll endian64
#define network_htonll endian64
#define network_ntohl ntohl
#define network_htonl htonl
#define network_ntohs ntohs
#define network_htons htons

#if defined(PLATFORM_ESP32)

#include "driver_network_esp32.h"

#define network_init() esp_network_init()
#define network_connected() esp_network_connected()
#define network_tcp_server esp_network_tcp_server
#define network_tcp_accept esp_network_tcp_accept
#define network_tcp_client(host, port) esp_network_tcp_client(host, port)
#define network_tcp_connected(fp) esp_network_tcp_connected(fp)
#define network_tcp_recv esp_network_tcp_recv
#define network_tcp_send esp_network_tcp_send
#define network_tcp_close esp_network_close
#define network_udp_create esp_network_udp_create
#define network_udp_recv esp_network_udp_recv
#define network_udp_send esp_network_udp_send
#define network_udp_close esp_network_close
#define network_net_ip(ip) esp_network_ip(ip)
#define network_net_mask(ip) esp_network_mask(ip)
#define network_net_nat(ip) esp_network_nat(ip)
#define network_net_dns_pri(ip) esp_network_dns_primary(ip)
#define network_net_dns_sec(ip) esp_network_dns_secondary(ip)
#define network_net_mac(mac) esp_network_mac(mac)

#elif defined(PLATFORM_LINUX)

#include "driver_network_linux.h"

#define network_init linux_network_init
#define network_connected() linux_network_connected()
#define network_tcp_server linux_network_tcp_server
#define network_tcp_accept linux_network_tcp_accept
#define network_tcp_client(host, port) linux_network_tcp_client(host, port)
#define network_tcp_connected(fp) linux_network_tcp_connected(fp)
#define network_tcp_recv linux_network_tcp_recv
#define network_tcp_send linux_network_tcp_send
#define network_tcp_close linux_network_close
#define network_udp_create linux_network_udp_create
#define network_udp_recv linux_network_udp_recv
#define network_udp_send linux_network_udp_send
#define network_udp_close linux_network_close
#define network_net_ip(ip) linux_network_ip(ip)
#define network_net_mask(ip) linux_network_mask(ip)
#define network_net_nat(ip) linux_network_nat(ip)
#define network_net_dns_pri(ip) linux_network_dns_pri(ip);
#define network_net_dns_sec(ip) linux_network_dns_sec(ip);
#define network_net_mac(mac) linux_network_mac(mac)
#define network_net_set(ip, netmask, gateway, pridns, secdns, mac)

#endif

#ifdef __cplusplus
}
#endif

#endif
