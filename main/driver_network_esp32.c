#include "driver_esp32.h"

#if defined(PLATFORM_ESP32)

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <errno.h>
#include "sigma_log.h"
#include "esp_wifi.h"

static esp_netif_t *_netif = 0;

static uint8_t _sta_status = SIGMA_WIFI_STA_STATUS_DISCONNECTED;
static WifiAPListCallback _ap_list_cb = 0;

static void event_handler(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data)
{
    if (WIFI_EVENT == event_base && WIFI_EVENT_STA_START == event_id)
    {
        SigmaLogAction(0, 0, "STA start!\r\n");
        _sta_status = SIGMA_WIFI_STA_STATUS_CONNECTING;
    }
    else if (WIFI_EVENT == event_base && WIFI_EVENT_STA_DISCONNECTED == event_id)
    {
        SigmaLogAction(0, 0, "STA disconnect!\r\n");
        _sta_status = SIGMA_WIFI_STA_STATUS_DISCONNECTED;
    }
    else if (WIFI_EVENT == event_base && WIFI_EVENT_SCAN_DONE == event_id)
    {
        uint16_t i, count = 0;
        wifi_ap_record_t *record = 0;

        esp_wifi_scan_get_ap_num(&count);
        SigmaLogAction(0, 0, "scan ap count:%u", count);
        if (count)
        {
            record = malloc(count * sizeof(wifi_ap_record_t));
            if (record)
            {
                if (esp_wifi_scan_get_ap_records(&count, record) != ESP_OK)
                {
                    free(record);
                    record = 0;
                }
            }
        }
        WifiAPList *list = 0;
        if (count && record)
        {
            wifi_ap_record_t *r = record;
            list = (WifiAPList *)malloc(sizeof(WifiAPList) * count);

            for (i = 0; i < count; i++)
            {
                WifiAPList *ap = list + i;
                ap->ssid = (char *)r->ssid;
                ap->bssid = r->bssid;
                ap->channel = r->primary;
                ap->security = r->authmode;
                ap->rssi = r->rssi;

                r++;

                SigmaLogAction(0, 0, "ssid:%s bssid:%02x%02x%02x%02x%02x%02x", 
                        ap->ssid, 
                        ap->bssid[0],
                        ap->bssid[1],
                        ap->bssid[2],
                        ap->bssid[3],
                        ap->bssid[4],
                        ap->bssid[5]);
            }
        }
        if (_ap_list_cb)
            _ap_list_cb(list, count);
        _ap_list_cb = 0;

        if (list)
            free(list);
        if (record)
            free(record);
    }
    else if (IP_EVENT == event_base && IP_EVENT_STA_GOT_IP == event_id)
    {
        SigmaLogAction(0, 0, "STA got ip!\r\n");
        _sta_status = SIGMA_WIFI_STA_STATUS_CONNECTED;
    }
}

void esp_network_init(void)
{
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    _netif = esp_netif_create_default_wifi_sta();
    if (!_netif)
    {
        SigmaLogError(0, 0, "esp_netif_create_default_wifi_sta failed");
        return;
    }

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &event_handler, NULL));

    ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_STA) );
    ESP_ERROR_CHECK( esp_wifi_start() );
}

int esp_network_connected(void)
{
    return SIGMA_WIFI_STA_STATUS_CONNECTED == _sta_status;
}

int esp_network_tcp_server(uint16_t port)
{
    int fp = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fp < 0)
    {
        SigmaLogError(0, 0, "errno:%d error:%s", errno, strerror(errno));
        return -1;
    }

    int sock_opts = 1;
    setsockopt(fp, SOL_SOCKET, SO_REUSEADDR, (void*)&sock_opts, sizeof(sock_opts));
    sock_opts = fcntl(fp, F_GETFL);
    sock_opts |= O_NONBLOCK;
    fcntl(fp, F_SETFL, sock_opts);

    struct sockaddr_in saLocal;
    saLocal.sin_family = AF_INET;
    saLocal.sin_port = htons(port);
    saLocal.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(fp, (struct sockaddr *)&saLocal, sizeof(struct sockaddr_in)) < 0)
    {
        SigmaLogError(0, 0, "errno:%d error:%s", errno, strerror(errno));
        close(fp);
        return -1;
    }
    if (listen(fp, 5) < 0)
    {
        SigmaLogError(0, 0, "errno:%d error:%s", errno, strerror(errno));
        close(fp);
        return -1;
    }
    return fp;
}

static int esp_select(int fp, int read, int write)
{
    int ret = 0;

    fd_set fsr;
    FD_ZERO(&fsr);
    FD_SET(fp, &fsr);

    fd_set fsw;
    FD_ZERO(&fsw);
    FD_SET(fp, &fsw);

    fd_set fse;
    FD_ZERO(&fse);
    FD_SET(fp, &fse);

    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 0;

    ret = select(fp + 1, (read ? &fsr : 0), (write ? &fsw : 0), &fse, (struct timeval *)&tv);
    if (ret < 0)
    {
        SigmaLogError(0, 0, "fp:%d errno:%u error:%s", fp, errno, strerror(errno));
        return -1;
    }
    if (!ret)
        return 0;
    ret = 0;

    if (FD_ISSET(fp, &fse))
    {
        if (EINPROGRESS != errno && EALREADY != errno)
        {
            SigmaLogError(0, 0, "fp:%d errno:%u error:%s", fp, errno, strerror(errno));
            return -1;
        }
    }
    if (read && FD_ISSET(fp, &fsr))
        ret |= 0x01;
    if (write && FD_ISSET(fp, &fsw))
        ret |= 0x02;

    int error = 0;
    socklen_t length = sizeof(int);
    if (getsockopt(fp, SOL_SOCKET, SO_ERROR, (void *)&error, &length) < 0)
    {
        SigmaLogError(0, 0, "fp:%d errno:%u error:%s", fp, errno, strerror(errno));
        return -1;
    }
    if (error)
    {
        SigmaLogError(0, 0, "errno:%d error:%s", error, strerror(error));
        return -1;
    }
    return ret;
}

int esp_network_tcp_accept(int fp, uint8_t *ip, uint16_t *port)
{
    int ret = esp_select(fp, 1, 0);
    if (ret < 0)
        return ret;
    if (!ret)
        return -1;

    struct sockaddr_in sa;
    int salen = sizeof(sa);
    int conn = accept(fp, (struct sockaddr *)&sa, (socklen_t *)&salen);
    if (conn < 0)
    {
        if (EAGAIN == errno || EINTR == errno || EWOULDBLOCK == errno)
            return -1;
        SigmaLogError(0, 0, "error ret:%d(%s)", conn, strerror(errno));
        return -2;
    }
    *port = sa.sin_port;
    ip[0] = (uint8_t)(sa.sin_addr.s_addr >> 24);
    ip[1] = (uint8_t)(sa.sin_addr.s_addr >> 16);
    ip[2] = (uint8_t)(sa.sin_addr.s_addr >> 8);
    ip[3] = (uint8_t)(sa.sin_addr.s_addr >> 0);
    return conn;
}

static struct _hostname
{
    struct _hostname *_next;

    uint32_t timer;

    uint8_t addr[sizeof(((struct sockaddr_in *)0)->sin_addr)];

    char host[];
} *_hostnames = 0;
TaskHandle_t _thread_hostname = NULL;

static void thread_hostname( void * pvParameters )
{
    while (1)
    {
        struct _hostname *hn = _hostnames;
        while (hn)
        {
            if (!hn->timer || os_ticks_from(hn->timer) > os_ticks_ms(60000))
            {
                struct addrinfo hints, *res, *rel;
                memset(&hints, 0, sizeof (hints));
                hints.ai_family = PF_UNSPEC;
                hints.ai_socktype = SOCK_STREAM;
                hints.ai_flags |= AI_CANONNAME;

                if (getaddrinfo(hn->host, 0, &hints, &res))
                {
                    SigmaLogError(0, 0, "getaddrinfo %s failed.(%s)", hn->host, strerror(errno));
                }
                else
                {
                    rel = res;
                    while (res && AF_INET != res->ai_family)
                        res = res->ai_next;
                    if (res)
                    {
                        os_memcpy(hn->addr, &((struct sockaddr_in *) res->ai_addr)->sin_addr, sizeof(((struct sockaddr_in *) res->ai_addr)->sin_addr));
                        hn->timer = os_ticks();
                    }
                    if (rel)
                        freeaddrinfo(rel);
                }
            }
            hn = hn->_next;
        }
        vTaskSuspend(0);
    }
}

int esp_network_tcp_client(const char *host, uint16_t port)
{
    struct _hostname *hn = _hostnames;
    while (hn)
    {
        if (!os_strcmp(host, hn->host))
            break;
        hn = hn->_next;
    }
    if (!hn)
    {
        hn = os_malloc(sizeof(struct _hostname) + os_strlen(host) + 1);
        if (!hn)
        {
            SigmaLogError(0, 0, "out of memcpy");
            return -1;
        }
        os_memset(hn, 0, sizeof(struct _hostname));
        os_strcpy(hn->host, host);
        hn->_next = _hostnames;
        _hostnames = hn;

        if (!_thread_hostname)
            xTaskCreate(thread_hostname, "hostname", 2048, 0, tskIDLE_PRIORITY, &_thread_hostname);
        vTaskResume(_thread_hostname);
    }
    if (!hn->timer)
    {
        SigmaLogError(0, 0, "hostname %s not ready.", host);
        return -1;
    }
    if (os_ticks_from(hn->timer) > os_ticks_ms(300000))
        vTaskResume(_thread_hostname);

    int fp = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fp < 0)
    {
        SigmaLogError(0, 0, "create socket failed:(%d)%s", errno, strerror(errno));
        return -1;
    }

    int sock_opts = 1;
    setsockopt(fp, SOL_SOCKET, SO_REUSEADDR, (void*)&sock_opts, sizeof(sock_opts));
    sock_opts = fcntl(fp, F_GETFL);
    sock_opts |= O_NONBLOCK;
    fcntl(fp, F_SETFL, sock_opts);

    struct sockaddr_in sa;
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    os_memcpy(&sa.sin_addr, hn->addr, sizeof(sa.sin_addr));

    int ret = connect(fp, (struct sockaddr *)&sa, sizeof(sa));
    if (ret < 0)
    {
        if (EINPROGRESS != errno && errno != EALREADY && errno != EISCONN)
        {
            close(fp);
            SigmaLogError(0, 0, "%d connect failed. %s", fp, strerror(errno));
            return -1;
        }
    }
    return fp;
}

int esp_network_tcp_connected(int fp)
{
    return esp_select(fp, 0, 1);
}

int esp_network_tcp_recv(int fp, void *buffer, uint32_t size)
{
    int ret = esp_select(fp, 1, 0);
    if (ret < 0)
        return ret;
    if (!ret)
        return 0;

    ret = recv(fp, buffer, size, MSG_DONTWAIT);
    if (!ret)
    {
        SigmaLogError(0, 0, "%d closed by remote", fp);
        return -1;
    }
    if (ret < 0)
    {
        if (ENOTCONN == errno || EAGAIN == errno || EWOULDBLOCK == errno)
            return 0;
        SigmaLogError(0, 0, "%d closed by error(%u:%s)", fp, errno, strerror(errno));
        return -1;
    }
    return ret;
}

int esp_network_tcp_send(int fp, const void *buffer, uint32_t size)
{
    int ret = esp_select(fp, 0, 1);
    if (ret < 0)
        return ret;
    if (!ret)
        return 0;

    ret = send(fp, buffer, size, 0);
    if (!ret)
    {
        SigmaLogError(0, 0, "fp:%d remote close", fp);
        return -1;
    }
    if (ret < 0)
    {
        if (EAGAIN == errno || EWOULDBLOCK == errno)
            return 0;
        SigmaLogError(0, 0, "fp:%d error:%s", fp, strerror(errno));
        return -1;
    }
    return ret;
}

int esp_network_udp_create(uint16_t port)
{
    int fp = socket(AF_INET, SOCK_DGRAM, 0);

    int sock_opts = 1;
    setsockopt(fp, SOL_SOCKET, SO_BROADCAST, (void*)&sock_opts, sizeof(sock_opts));
    sock_opts = 1;
    setsockopt(fp, SOL_SOCKET, SO_REUSEADDR, (void*)&sock_opts, sizeof(sock_opts));
    sock_opts = 1;
    setsockopt(fp, SOL_SOCKET, SO_REUSEPORT, (void*)&sock_opts, sizeof(sock_opts));
    sock_opts = fcntl(fp, F_GETFL);
    sock_opts |= O_NONBLOCK;
    fcntl(fp, F_SETFL, sock_opts);

    if (port)
    {
        struct sockaddr_in saLocal;
        saLocal.sin_family = AF_INET;
        saLocal.sin_port = htons(port);
        saLocal.sin_addr.s_addr = inet_addr("0.0.0.0");

        if (bind(fp, (struct sockaddr *)&saLocal, sizeof(struct sockaddr_in)) < 0)
        {
            close(fp);
            return -2;
        }
    }
    return fp;
}

int esp_network_udp_recv(int fp, void *buffer, uint32_t size, uint8_t *ip, uint16_t *port)
{
    int ret = esp_select(fp, 1, 0);
    if (ret < 0)
        return ret;
    if (!ret)
        return 0;

    struct sockaddr_in sa;
    socklen_t len = sizeof(struct sockaddr_in);
    ret = recvfrom(fp, buffer, size, MSG_DONTWAIT, (struct sockaddr *)&sa, &len);
    if (!ret)
    {
        SigmaLogError(0, 0, "%d closed", fp);
        return -1;
    }
    if (ret < 0)
    {
        if (EAGAIN == errno || EWOULDBLOCK == errno)
            return 0;
        SigmaLogError(0, 0, "%d closed by error(%u:%s)", fp, errno, strerror(errno));
        return -1;
    }
    *port = ntohs(sa.sin_port);
    *(uint32_t *)ip = sa.sin_addr.s_addr;
    return ret;
}

int esp_network_udp_send(int fp, const void *buffer, uint32_t size, const uint8_t *ip, uint16_t port)
{
    int ret = esp_select(fp, 0, 1);
    if (ret < 0)
        return ret;
    if (!ret)
        return 0;

    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = *(uint32_t *)ip;
    ret = sendto(fp, buffer, size, 0, (const struct sockaddr *)&sa, (socklen_t)sizeof(struct sockaddr_in));
    if (!ret)
    {
        SigmaLogError(0, 0, "%d closed by remote", fp);
        return -1;
    }
    if (ret < 0)
    {
        if (EAGAIN == errno || EWOULDBLOCK == errno)
            return 0;
        SigmaLogError(0, 0, "%d closed by error(%s)", fp, strerror(errno));
        return -1;
    }
    return ret;
}

int esp_network_close(int fp)
{
    return close(fp);
}

int esp_network_ip(uint8_t *ip)
{
    esp_netif_ip_info_t ip_info;
    esp_netif_get_ip_info(_netif, &ip_info);
    *(uint32_t *)ip = ip_info.ip.addr;

    return 4;
}

int esp_network_mask(uint8_t *mask)
{
    esp_netif_ip_info_t ip_info;
    esp_netif_get_ip_info(_netif, &ip_info);
    *(uint32_t *)mask = ip_info.netmask.addr;

    return 4;
}

int esp_network_nat(uint8_t *nat)
{
    esp_netif_ip_info_t ip_info;
    esp_netif_get_ip_info(_netif, &ip_info);
    *(uint32_t *)nat = ip_info.gw.addr;

    return 4;
}

int esp_network_mac(uint8_t *mac)
{
    esp_netif_get_mac(_netif, mac);
    return 6;
}

int esp_network_dns_primary(uint8_t *dns)
{
    esp_netif_dns_info_t dns_info;
    ESP_ERROR_CHECK(esp_netif_get_dns_info(_netif, ESP_NETIF_DNS_MAIN, &dns_info));
    *(uint32_t *)dns = dns_info.ip.u_addr.ip4.addr;

    return 4;
}

int esp_network_dns_secondary(uint8_t *dns)
{
    esp_netif_dns_info_t dns_info;
    ESP_ERROR_CHECK(esp_netif_get_dns_info(_netif, ESP_NETIF_DNS_BACKUP, &dns_info));
    *(uint32_t *)dns = dns_info.ip.u_addr.ip4.addr;

    return 4;
}

void esp_network_wifi_ap_connect(const char *ssid, const char *password, const uint8_t *bssid)
{
    SigmaLogAction(0, 0, "wifi connecting(ssid:%s, pwd:%s)", ssid, password);

    ESP_ERROR_CHECK( esp_wifi_disconnect() );

    wifi_config_t wifi_config = {0};
    if (ssid)
        memcpy(wifi_config.sta.ssid, ssid, 32);
    if (password)
        memcpy(wifi_config.sta.password, password, 64);
    if (bssid)
        memcpy(wifi_config.sta.bssid, bssid, 6);

    ESP_ERROR_CHECK( esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config) );
    ESP_ERROR_CHECK( esp_wifi_connect() );
}

void esp_network_wifi_ap_disconnect(void)
{
    SigmaLogAction(0, 0, "wifi disconnecting");

    ESP_ERROR_CHECK( esp_wifi_disconnect() );
}

int esp_network_wifi_sta_status(void)
{
    return _sta_status;
}

int esp_network_wifi_ap_rssi(void)
{
    wifi_ap_record_t info;
    esp_wifi_sta_get_ap_info(&info);
    return info.rssi;
}

void esp_network_wifi_scan_ap(const uint8_t *bssid, WifiAPListCallback cb)
{
    SigmaLogAction(0, 0, "search ap list");

    _ap_list_cb = cb;

    wifi_scan_config_t scan_config = { 0 };
    scan_config.bssid = (uint8_t *)bssid;

    ESP_ERROR_CHECK( esp_wifi_scan_start(&scan_config, false) );
}

static WifiSnifferCallback _sniffer_cb = 0;

static void wifi_sniffer_cb(void *recv_buf, wifi_promiscuous_pkt_type_t type)
{
    wifi_promiscuous_pkt_t *sniffer = (wifi_promiscuous_pkt_t *)recv_buf;

    if (_sniffer_cb)
        _sniffer_cb(sniffer->payload, sniffer->rx_ctrl.sig_len);
}

void esp_network_wifi_sniffer_callback(WifiSnifferCallback cb)
{
    _sniffer_cb = cb;
    esp_wifi_set_promiscuous_rx_cb(wifi_sniffer_cb);
}

void esp_network_wifi_sniffer_channel(uint8_t channel, int8_t modifier)
{
    if (!modifier)
    {
        esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    }
    else if (modifier > 0)
    {
        esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_ABOVE);
    }
    else
    {
        esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_BELOW);
    }
}

void esp_network_wifi_sniffer_start(void)
{
    _sta_status = SIGMA_WIFI_STA_STATUS_DISCONNECTED;

    esp_wifi_disconnect();

    wifi_promiscuous_filter_t wifi_filter;
    wifi_filter.filter_mask = WIFI_PROMIS_FILTER_MASK_DATA | WIFI_PROMIS_FILTER_MASK_DATA_MPDU | WIFI_PROMIS_FILTER_MASK_DATA_AMPDU;
    esp_wifi_set_promiscuous_filter(&wifi_filter);

    ESP_ERROR_CHECK( esp_wifi_set_promiscuous(true) );
}

void esp_network_wifi_sniffer_stop(void)
{
    _sniffer_cb = 0;
    esp_wifi_set_promiscuous(false);
}

void esp_network_wifi_sniffer_send(const uint8_t *frame, uint32_t size)
{
    esp_wifi_80211_tx(ESP_IF_WIFI_STA, frame, size, false);
}

#endif
