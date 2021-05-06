#include "sigma_log.h"
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include "hex.h"
#if defined(PLATFORM_ANDROID)
#include <android/log.h>
#endif

#if defined(PLATFORM_WSL) 
#include <syslog.h>
#endif

#define ENABLE_SCREEN_LOG

static uint8_t color_hash(const char *s)
{
    uint32_t hash = 0;
    int i = strlen(s);
    while (i--)
    {
        hash <<= 1;
        hash += s[i];
    }
    return ((hash >> 1) % 9) + 1;
}

void sigma_log_println(const char *file, uint32_t line, const char *func, unsigned char level, const void *buffer, size_t size, const char *fmt, ...)
{
    uint32_t i = strlen(__FILE__) - strlen("sigma_log.c");

    file += i;

#ifdef PLATFORM_ANDROID
    int prio = 0;
    prio = ANDROID_LOG_DEBUG;
    if (LOG_LEVEL_ERROR == level)
        prio = ANDROID_LOG_ERROR;
    else if (LOG_LEVEL_ACTION == level)
        prio = ANDROID_LOG_INFO;

    char format[1024] = {0};
    sprintf(format, "%d/%s/%s", line, func, fmt);
    if (size)
    {
        i = strlen(format);
        if (size > (1024 - i - 1) / 2)
            size = (1024 - i - 1) / 2;
        bin2hex(format + i, buffer, size);
    }
    
    va_list args;
    va_start(args, fmt);
    __android_log_vprint(prio, file, format, args);
    va_end(args);
#else
    va_list args;
#ifdef PLATFORM_WSL //{
    int prio = 0;
    prio = LOG_DEBUG;
    if (LOG_LEVEL_ERROR == level)
        prio = LOG_ERR;
    else if (LOG_LEVEL_ACTION == level)
        prio = LOG_INFO;
    
    char format[1024] = {0};
    sprintf(format, "%s:%d %s %s", file, line, func, fmt);
    if (size)
    {
        i = strlen(format);
        if (size > (1024 - i - 1) / 2)
            size = (1024 - i - 1) / 2;
        bin2hex(format + i, buffer, size);
    }
    
    va_start(args, fmt);
    vsyslog(prio, format, args);
    va_end(args);
#endif //}
#ifdef ENABLE_SCREEN_LOG //{
    time_t now = time(0);
    struct tm *t = localtime(&now);
    
    i = strlen(file);
    if (i > 20)
        file += i - 20;

    i = strlen(func);
    if (i > 15)
        func += i - 15;

    i = 0;
    if (LOG_LEVEL_ERROR == level)
        i = 31;
    else if (LOG_LEVEL_DEBUG == level)
        i = 32;

    printf("\033[0m%02d:%02d:%02d|%20s:%4u|\033[3%dm%15s\033[0m|\033[%dm",
        t->tm_hour, t->tm_min, t->tm_sec, 
        file, line, color_hash(func), func,
        i);

    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);

    for (i = 0; i < size; i++)
        printf("%02x ", *(((unsigned char *)buffer) + i));

    printf("\033[0m\n");

    fflush(stdout);
#endif//}
#endif
}
