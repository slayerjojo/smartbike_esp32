#ifndef __DRIVER_ESP32_H__
#define __DRIVER_ESP32_H__

#include "env.h"
#include "interface_network.h"
#include "interface_os.h"

#ifdef __cplusplus
extern "C"
{
#endif

uint32_t esp_ticks(void);
uint32_t esp_ticks_from(uint32_t start);

#ifdef __cplusplus
}
#endif

#endif
