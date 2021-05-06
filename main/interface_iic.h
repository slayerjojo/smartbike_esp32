#ifndef __INTERFACE_IIC_H__
#define __INTERFACE_IIC_H__

#include "env.h"

#ifdef PLATFORM_ESP32

#include "driver_iic_esp32.h"

#define iic_master_open(port, freq) esp32_iic_master_open(port, freq)
#define iic_close(port) esp32_iic_close(port)
#define iic_master_write(port, addr, reg, data, length, timeout) esp32_iic_master_write(port, addr, reg, data, length, timeout)
#define iic_master_read(port, addr, reg, data, length, timeout) esp32_iic_master_read(port, addr, reg, data, length, timeout)
#define iic_master_bwrite(port, addr, reg, bit, data, length, timeout) esp32_iic_master_bitwrite(port, addr, reg, bit, data, length, timeout)
#define iic_master_bget(port, addr, reg, bit, timeout) esp32_iic_master_bitget(port, addr, reg, bit, timeout)
#define iic_master_bset(port, addr, reg, bit, timeout) esp32_iic_master_bitset(port, addr, reg, bit, timeout)
#define iic_master_bclear(port, addr, reg, bit, timeout) esp32_iic_master_bitclear(port, addr, reg, bit, timeout)

#endif

#endif
