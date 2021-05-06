#ifndef __INTERFACE_OS_H__
#define __INTERFACE_OS_H__

#ifdef __cplusplus
extern "C"
{
#endif

#include "env.h"

#if defined(PLATFORM_ESP32)

#include "driver_esp32.h"

#define os_init()
#define os_update()

#define os_malloc malloc
#define os_free free
#define os_realloc realloc
#define os_memset memset
#define os_memcpy memcpy
#define os_memcmp memcmp
#define os_memmove memmove
#define os_strlen strlen
#define os_strstr strstr
#define os_strcpy strcpy
#define os_strcmp strcmp
#define os_ticks esp_ticks
#define os_sleep(ms) usleep(ms * 1000)
#define os_rand esp_random
#define os_time time
#define os_localtime localtime

#define os_ticks_ms(ms) (ms)
#define os_ticks_from esp_ticks_from

#define os_ota_init(module) esp_ota_init(module)
#define os_ota_process() esp_ota_process()

#define os_restart() esp_restart()

#elif defined(PLATFORM_LINUX)

#include "driver_linux.h"

#define os_init()
#define os_update()

#define os_malloc malloc
#define os_free free
#define os_realloc realloc
#define os_memset memset
#define os_memcpy memcpy
#define os_memcmp memcmp
#define os_memmove memmove
#define os_strlen strlen
#define os_strstr strstr
#define os_strcpy strcpy
#define os_strcat strcat
#define os_strcmp strcmp
#define os_ticks linux_ticks
#define os_sleep usleep
#define os_rand rand
#define os_time time
#define os_localtime localtime

#define os_ticks_ms(ms) (ms)
#define os_ticks_from linux_ticks_from

#define os_ota_init(module)
#define os_ota_process() 1

#define os_restart()

#endif

#ifdef __cplusplus
}
#endif

#endif
