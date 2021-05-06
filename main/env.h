#ifndef __ENV_H__
#define __ENV_H__

#define PLATFORM_ESP32

#ifdef PLATFORM_ESP32
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "esp_eth.h"
#include "esp_event.h"
#include "esp_wifi.h"
#include "esp_system.h"
#include "esp_http_client.h"
#include "esp_netif.h"
#include "driver/uart.h"
#include "driver/gpio.h"
#include "driver/i2c.h"
#endif

#endif
