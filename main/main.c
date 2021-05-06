#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_spi_flash.h"
#include "nvs_flash.h"
#include "esp_task_wdt.h"
#include "soc/timer_group_struct.h"
#include "soc/timer_group_reg.h"

#include "sdkconfig.h"
#include "esp_log.h"
#include "esp_console.h"
#include "esp_vfs_fat.h"
#include "sigma_log.h"
#include "driver_mpu6050.h"
#include "interface_os.h"
#include "env.h"

void app_main(void)
{
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
      ESP_ERROR_CHECK(nvs_flash_erase());
      ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    mpu6050_init();

    while (1)
    {
        TIMERG0.wdt_wprotect=TIMG_WDT_WKEY_VALUE;
        TIMERG0.wdt_feed=1;
        TIMERG0.wdt_wprotect=0;

        mpu6050_update();

        int16_t ax, ay, az, gx, gy, gz, temp;
        if (mpu6050_motion(&ax, &ay, &az, &gx, &gy, &gz, &temp) < 0)
            continue;
        float
        SigmaLogAction(0, 0, "accel:%d %d %d gyro:%d %d %d temp:%d", ax, ay, az, gx, gy, gz, temp);
        os_sleep(1000);
    }
}
