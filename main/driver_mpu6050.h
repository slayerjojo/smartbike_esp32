#ifndef __DRIVER_MPU6050_H__
#define __DRIVER_MPU6050_H__

#include "env.h"

void mpu6050_init(void);
void mpu6050_update(void);

int mpu6050_reset(void);
int mpu6050_whoami(void);
int mpu6050_sample_rate(uint16_t rate);
int mpu6050_acceleration(int16_t *x, int16_t *y, int16_t *z);
int mpu6050_rotation(int16_t *x, int16_t *y, int16_t *z);
int mpu6050_temperature(int16_t *temp);
int mpu6050_motion(int16_t *ax, int16_t *ay, int16_t *az, int16_t *gx, int16_t *gy, int16_t *gz, int16_t *temp);
int mpu6050_self_test(void);
int mpu6050_accel_gravity(const int16_t *in, float out);
int mpu6050_gyro_degree(const int16_t *in, float *out);

#endif
