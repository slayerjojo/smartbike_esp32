#ifndef __DRIVER_IIC_ESP32_H__
#define __DRIVER_IIC_ESP32_H__

#include "env.h"

int esp32_iic_master_open(uint8_t port, uint32_t freq);
int esp32_iic_close(uint8_t port);
int esp32_iic_master_write(uint8_t port, uint8_t addr, uint8_t reg, uint8_t *data, uint32_t length, uint32_t timeout);
int esp32_iic_master_read(uint8_t port, uint8_t addr, uint8_t reg, uint8_t *data, uint32_t length, uint32_t timeout);
int esp32_iic_master_bitwrite(uint8_t port, uint8_t addr, uint8_t reg, uint8_t bit, uint8_t value, uint8_t length, uint32_t timeout);
int esp32_iic_master_bitget(uint8_t port, uint8_t addr, uint8_t reg, uint8_t bit, uint32_t timeout);
int esp32_iic_master_bitset(uint8_t port, uint8_t addr, uint8_t reg, uint8_t bit, uint32_t timeout);
int esp32_iic_master_bitclear(uint8_t port, uint8_t addr, uint8_t reg, uint8_t bit, uint32_t timeout);

#endif
