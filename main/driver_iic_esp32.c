#include "driver_iic_esp32.h"
#include "driver/i2c.h"
#include "driver/gpio.h"
#include "sigma_log.h"

#define I2C_GPIO_SDA 18
#define I2C_GPIO_SCL 23

int esp32_iic_master_open(uint8_t port, uint32_t freq)
{
    i2c_config_t conf = {
        .mode = I2C_MODE_MASTER,
        .sda_io_num = I2C_GPIO_SDA,
        .sda_pullup_en = GPIO_PULLUP_ENABLE,
        .scl_io_num = I2C_GPIO_SCL,
        .scl_pullup_en = GPIO_PULLUP_ENABLE,
        .master.clk_speed = freq,
    };
    i2c_port_t p = I2C_NUM_0;
    if (1 == port)
        p = I2C_NUM_1;
    esp_err_t ret = i2c_param_config(p, &conf);
    if (ret != ESP_OK)
    {
        SigmaLogError(0, 0, "i2c_param_config error.(err:%d)", ret);
        return -1;
    }
    ret = i2c_driver_install(p, conf.mode, 0, 0, 0);
    if (ret != ESP_OK)
    {
        SigmaLogError(0, 0, "i2c_driver_install error.(err:%d)", ret);
        return -1;
    }
    return 0;
}

int esp32_iic_close(uint8_t port)
{
    i2c_port_t p = I2C_NUM_0;
    if (1 == port)
        p = I2C_NUM_1;
    i2c_driver_delete(p);
    return 0;
}

int esp32_iic_master_write(uint8_t port, uint8_t addr, uint8_t reg, uint8_t *data, uint32_t length, uint32_t timeout)
{
    i2c_cmd_handle_t cmd = i2c_cmd_link_create();
    i2c_master_start(cmd);
    i2c_master_write_byte(cmd, (addr << 1) | I2C_MASTER_WRITE, true);
    i2c_master_write_byte(cmd, reg, true);
    i2c_master_write(cmd, (uint8_t *)data, length, true);
    i2c_master_stop(cmd);
    
    i2c_port_t p = I2C_NUM_0;
    if (1 == port)
        p = I2C_NUM_1;
    esp_err_t err = i2c_master_cmd_begin(p, cmd, timeout / portTICK_RATE_MS);
    i2c_cmd_link_delete(cmd);
    if (err != ESP_OK)
    {
        SigmaLogError(data, length, "failed.(addr:%08x reg:%08x) data:", addr, reg);
        return -1;
    }
    return 0;
}

int esp32_iic_master_read(uint8_t port, uint8_t addr, uint8_t reg, uint8_t *data, uint32_t length, uint32_t timeout)
{
    i2c_cmd_handle_t cmd = i2c_cmd_link_create();
    i2c_master_start(cmd);
    i2c_master_write_byte(cmd, (addr << 1) | I2C_MASTER_WRITE, true);
    i2c_master_write_byte(cmd, reg, true);
    i2c_master_start(cmd);
    i2c_master_write_byte(cmd, (addr << 1) | I2C_MASTER_READ, true);
    i2c_master_read(cmd, data, length, I2C_MASTER_LAST_NACK);
    i2c_master_stop(cmd);
    
    i2c_port_t p = I2C_NUM_0;
    if (1 == port)
        p = I2C_NUM_1;
    esp_err_t err = i2c_master_cmd_begin(p, cmd, timeout / portTICK_RATE_MS);
    i2c_cmd_link_delete(cmd);
    if (err != ESP_OK)
    {
        SigmaLogError(0, 0, "failed.(addr:%02x reg:%02x)", addr, reg);
        return -1;
    }
    return 0;
}

int esp32_iic_master_bitwrite(uint8_t port, uint8_t addr, uint8_t reg, uint8_t bit, uint8_t value, uint8_t length, uint32_t timeout)
{
    uint8_t data;
    if (esp32_iic_master_read(port, addr, reg, &data, 1, timeout) < 0)
        return -1;
    uint8_t mask = ((1 << length) - 1) << (bit - length + 1);
    value <<= (bit - length + 1);
    data &= ~mask;
    data |= value;
    if (esp32_iic_master_write(port, addr, reg, &data, 1, timeout) < 0)
        return -1;
    return 0;
}

int esp32_iic_master_bitget(uint8_t port, uint8_t addr, uint8_t reg, uint8_t bit, uint32_t timeout)
{
    uint8_t data;
    if (esp32_iic_master_read(port, addr, reg, &data, 1, timeout) < 0)
        return -1;
    return !!(data & (1 << bit));
}

int esp32_iic_master_bitset(uint8_t port, uint8_t addr, uint8_t reg, uint8_t bit, uint32_t timeout)
{
    uint8_t data;
    if (esp32_iic_master_read(port, addr, reg, &data, 1, timeout) < 0)
        return -1;
    data |= 1 << bit;
    if (esp32_iic_master_write(port, addr, reg, &data, 1, timeout) < 0)
        return -1;
    return 0;
}

int esp32_iic_master_bitclear(uint8_t port, uint8_t addr, uint8_t reg, uint8_t bit, uint32_t timeout)
{
    uint8_t data;
    if (esp32_iic_master_read(port, addr, reg, &data, 1, timeout) < 0)
        return -1;
    data &= ~(1 << bit);
    if (esp32_iic_master_write(port, addr, reg, &data, 1, timeout) < 0)
        return -1;
    return 0;
}
