#include "driver_mpu6050.h"
#include "interface_iic.h"
#include "driver_mpu6050.h"
#include "mpu_registers.h"
#include "sigma_log.h"
#include "interface_os.h"

enum {
    MPU_STATE_INIT = 0,
    MPU_STATE_CONNECT,
    MPU_STATE_MPU_INIT,
    MPU_STATE_MPU_SERVICE,
};

typedef enum {  //
    MPU_I2CADDRESS_AD0_LOW  = 0x68,
    MPU_I2CADDRESS_AD0_HIGH = 0x69
} mpu_i2caddr_t;

/*! Clock Source */
typedef enum {
    CLOCK_INTERNAL = 0,  //!< Internal oscillator: 20MHz for MPU6500 and 8MHz for MPU6050
    CLOCK_PLL_X      = 1,
    CLOCK_PLL_Y      = 2,
    CLOCK_PLL_Z      = 3,
#if defined CONFIG_MPU6050
    CLOCK_EXT32KHZ = 4,  //!< PLL with external 32.768kHz reference
    CLOCK_EXT19MHZ = 5,  //!< PLL with external 19.2MHz reference
#endif
    CLOCK_KEEP_RESET = 7  //!< Stops the clock and keeps timing generator in reset
} clock_src_t;

/*! Gyroscope full-scale range */
typedef enum {
    GYRO_FS_250DPS  = 0,  //!< +/- 250 º/s  -> 131 LSB/(º/s)
    GYRO_FS_500DPS  = 1,  //!< +/- 500 º/s  -> 65.5 LSB/(º/s)
    GYRO_FS_1000DPS = 2,  //!< +/- 1000 º/s -> 32.8 LSB/(º/s)
    GYRO_FS_2000DPS = 3   //!< +/- 2000 º/s -> 16.4 LSB/(º/s)
} gyro_fs_t;

/*! Accel full-scale range */
typedef enum {
    ACCEL_FS_2G  = 0,  //!< +/- 2 g  -> 16.384 LSB/g
    ACCEL_FS_4G  = 1,  //!< +/- 4 g  -> 8.192 LSB/g
    ACCEL_FS_8G  = 2,  //!< +/- 8 g  -> 4.096 LSB/g
    ACCEL_FS_16G = 3   //!< +/- 16 g -> 2.048 LSB/g
} accel_fs_t;

/*! Digital low-pass filter (based on gyro bandwidth) */
typedef enum {
    DLPF_256HZ_NOLPF = 0,
    DLPF_188HZ       = 1,
    DLPF_98HZ        = 2,
    DLPF_42HZ        = 3,
    DLPF_20HZ        = 4,
    DLPF_10HZ        = 5,
    DLPF_5HZ         = 6,
#ifdef CONFIG_MPU6050
    DLPF_2100HZ_NOLPF = 7
#elif CONFIG_MPU6500
    DLPF_3600HZ_NOLPF     = 7
#endif
} dlpf_t;

#define MPU6050_I2C_CLOCK 100000
#define MPU6050_I2C_PORT 0
#define MPU6050_I2C_ADDR MPU_I2CADDRESS_AD0_LOW

#define MPU6050_I2C_TIMEOUT 1000

#define MPU6050_DIGITAL_LOW_PASS_FILTER DLPF_20HZ
#define MPU6050_SAMPLE_RATE 100
#define MPU6050_ACCEL_FULL_SCALE ACCEL_FS_16G
#define MPU6050_GYRO_FULL_SCALE GYRO_FS_2000DPS

static uint8_t _state = 0;

inline float gyro_sensitivity(const uint8_t fs)
{
    return 131.f / (1 << fs);
}

inline float gyro_resolution(const uint8_t fs)
{
    return (float)(250 << fs) / INT16_MAX;
}

inline void gyro_degree_per_second(const int16_t *axis, const uint8_t fs, float *result)
{
    result[0] = (float)axis[0] * gyro_resolution(fs);
    result[1] = (float)axis[1] * gyro_resolution(fs);
    result[2] = (float)axis[2] * gyro_resolution(fs);
}

inline float accel_sensitivity(const uint8_t fs)
{
    return 16384 >> fs;
}

inline float accel_resolution(const uint8_t fs)
{
    return (float)(2 << fs) / INT16_MAX;
}

inline void accel_gravity(const int16_t *axis, const uint8_t fs, float *result)
{
    result[0] = (float)axis[0] * accel_resolution(fs);
    result[1] = (float)axis[1] * accel_resolution(fs);
    result[2] = (float)axis[2] * accel_resolution(fs);
}

void mpu6050_init(void)
{
    _state = MPU_STATE_INIT;
}

void mpu6050_update(void)
{
    if (MPU_STATE_INIT == _state)
    {
        if (iic_master_open(0, MPU6050_I2C_CLOCK) < 0)
            return;
        _state = MPU_STATE_CONNECT;
    }
    if (MPU_STATE_CONNECT == _state)
    {
        int ret = mpu6050_whoami();
        if (ret < 0)
        {
            _state = MPU_STATE_INIT;
            return;
        }
        if (!ret)
            return;
        _state = MPU_STATE_MPU_INIT;
    }
    if (MPU_STATE_MPU_INIT == _state)
    {
        uint8_t setting = 1;
        if (mpu6050_reset() < 0)
            return;
        if (iic_master_bclear(MPU6050_I2C_PORT, MPU6050_I2C_ADDR, MPUR_PWR_MGMT1, MPUR_PWR1_SLEEP_BIT, MPU6050_I2C_TIMEOUT) < 0)
        {
            SigmaLogError(0, 0, "sleep failed.");
            return;
        }
        if (iic_master_bwrite(MPU6050_I2C_PORT, MPU6050_I2C_ADDR, MPUR_PWR_MGMT1, MPUR_PWR1_CLKSEL_BIT, CLOCK_PLL_X, MPUR_PWR1_CLKSEL_LENGTH, MPU6050_I2C_TIMEOUT) < 0)
        {
            SigmaLogError(0, 0, "clock source failed.");
            return;
        }
        if (iic_master_bwrite(MPU6050_I2C_PORT, MPU6050_I2C_ADDR, MPUR_GYRO_CONFIG, MPUR_GCONFIG_FS_SEL_BIT, MPU6050_GYRO_FULL_SCALE, MPUR_GCONFIG_FS_SEL_LENGTH, MPU6050_I2C_TIMEOUT) < 0)
        {
            SigmaLogError(0, 0, "gyro full scale failed.");
            return;
        }
        if (iic_master_bwrite(MPU6050_I2C_PORT, MPU6050_I2C_ADDR, MPUR_ACCEL_CONFIG, MPUR_ACONFIG_FS_SEL_BIT, MPU6050_ACCEL_FULL_SCALE, MPUR_ACONFIG_FS_SEL_LENGTH, MPU6050_I2C_TIMEOUT) < 0)
        {
            SigmaLogError(0, 0, "accel full scale failed.");
            return;
        }
        setting = 0xff;
        if (iic_master_write(MPU6050_I2C_PORT, MPU6050_I2C_ADDR, MPUR_FIFO_EN, &setting, 1, MPU6050_I2C_TIMEOUT) < 0)
        {
            SigmaLogError(0, 0, "fifo failed.");
            return;
        }
        if (iic_master_bclear(MPU6050_I2C_PORT, MPU6050_I2C_ADDR, MPUR_I2C_MST_CTRL, MPUR_I2CMST_CTRL_SLV_3_FIFO_EN_BIT, MPU6050_I2C_TIMEOUT) < 0)
        {
            SigmaLogError(0, 0, "fifo failed.");
            return;
        }

        if (mpu6050_sample_rate(MPU6050_SAMPLE_RATE) < 0)
            return;
        
        if (iic_master_bwrite(MPU6050_I2C_PORT, MPU6050_I2C_ADDR, MPUR_CONFIG, MPUR_CONFIG_DLPF_CFG_BIT, MPU6050_DIGITAL_LOW_PASS_FILTER, MPUR_CONFIG_DLPF_CFG_LENGTH, MPU6050_I2C_TIMEOUT) < 0)
        {
            SigmaLogError(0, 0, "digital low pass filter failed.");
            return;
        }

        setting = 0;
        if (iic_master_write(MPU6050_I2C_PORT, MPU6050_I2C_ADDR, MPUR_PWR_MGMT2, &setting, 1, MPU6050_I2C_TIMEOUT) < 0)
        {
            SigmaLogError(0, 0, "mgmt2 failed.");
            return;
        }
        _state = MPU_STATE_MPU_SERVICE;

        int result = mpu6050_self_test();
        SigmaLogAction(0, 0, "self test result:%d", result);
    }
}

int mpu6050_reset(void)
{
    if (iic_master_bset(MPU6050_I2C_PORT, MPU6050_I2C_ADDR, MPUR_PWR_MGMT1, MPUR_PWR1_DEVICE_RESET_BIT, MPU6050_I2C_TIMEOUT) < 0)
    {
        SigmaLogError(0, 0, "reset failed.");
        return -1;
    }
    os_sleep(100);
    return 0;
}

int mpu6050_whoami(void)
{
    uint8_t wai = 0;
    if (iic_master_read(MPU6050_I2C_PORT, MPU6050_I2C_ADDR, MPUR_WHO_AM_I, &wai, 1, MPU6050_I2C_TIMEOUT) < 0)
    {
        SigmaLogError(0, 0, "whoami failed.");
        return -1;
    }
    SigmaLogAction(0, 0, "who am i:%02x", wai);
    return 1;//wai == 0x68;
}

int mpu6050_sample_rate(uint16_t rate)
{
    if (!(4 <= rate && rate <= 1000))
    {
        SigmaLogError(0, 0, "rate:%d error.(range:[4, 1000]).", rate);
        return -1;
    }

    const int internalSampleRate = 1000;
    uint8_t divider = internalSampleRate / rate - 1;
    uint16_t finalRate = internalSampleRate / (1 + divider);
    if (finalRate != rate)
    {
        SigmaLogDebug(0, 0, "sample rate constrained to %d Hz", finalRate);
    }
    if (iic_master_write(MPU6050_I2C_PORT, MPU6050_I2C_ADDR, MPUR_SMPLRT_DIV, &divider, 1, MPU6050_I2C_TIMEOUT) < 0)
    {
        SigmaLogError(0, 0, "sample rate failed.");
        return -1;
    }
    return 0;
}

int mpu6050_aux_enable(bool enable)
{
    if (enable)
    {
        if (iic_master_bset(MPU6050_I2C_PORT, MPU6050_I2C_ADDR, MPUR_USER_CTRL, MPUR_USERCTRL_I2C_MST_EN_BIT, MPU6050_I2C_TIMEOUT) < 0)
            return -1;
        if (iic_master_bset(MPU6050_I2C_PORT, MPU6050_I2C_ADDR, MPUR_INT_PIN_CONFIG, MPUR_INT_CFG_I2C_BYPASS_EN_BIT, MPU6050_I2C_TIMEOUT) < 0)
            return -1;
    }
    else
    {
        if (iic_master_bclear(MPU6050_I2C_PORT, MPU6050_I2C_ADDR, MPUR_USER_CTRL, MPUR_USERCTRL_I2C_MST_EN_BIT, MPU6050_I2C_TIMEOUT) < 0)
            return -1;
    }
    return 0;
}

int mpu6050_aux_enabled(void)
{
    int ret = iic_master_bget(MPU6050_I2C_PORT, MPU6050_I2C_ADDR, MPUR_USER_CTRL, MPUR_USERCTRL_I2C_MST_EN_BIT, MPU6050_I2C_TIMEOUT);
    if (ret < 0)
        return -1;
    if (!ret)
        return 0;
    ret = iic_master_bget(MPU6050_I2C_PORT, MPU6050_I2C_ADDR, MPUR_INT_PIN_CONFIG, MPUR_INT_CFG_I2C_BYPASS_EN_BIT, MPU6050_I2C_TIMEOUT);
    if (ret < 0)
        return -1;
    return !ret;
}

int mpu6050_low_power_accelerometer_mode_set(bool enable)
{
    uint8_t pwr_mgmt[2] = {0};
    if (iic_master_read(MPU6050_I2C_PORT, MPU6050_I2C_ADDR, MPUR_PWR_MGMT1, pwr_mgmt, 2, MPU6050_I2C_TIMEOUT) < 0)
        return -1;

    if (enable)
    {
        pwr_mgmt[0] |= 1 << MPUR_PWR1_CYCLE_BIT;
        pwr_mgmt[0] &= ~(1 << MPUR_PWR1_SLEEP_BIT);
        pwr_mgmt[0] |= 1 << MPUR_PWR1_TEMP_DIS_BIT;
        pwr_mgmt[1] |= MPUR_PWR2_STBY_XYZG_BITS;
    }
    else
    {
        pwr_mgmt[0] &= ~(1 << MPUR_PWR1_CYCLE_BIT);
        pwr_mgmt[0] &= ~(1 << MPUR_PWR1_TEMP_DIS_BIT);
        pwr_mgmt[1] &= ~MPUR_PWR2_STBY_XYZG_BITS;
    }
    pwr_mgmt[1] &= ~MPUR_PWR2_STBY_XYZA_BITS;

    if (iic_master_write(MPU6050_I2C_PORT, MPU6050_I2C_ADDR, MPUR_PWR_MGMT1, pwr_mgmt, 2, MPU6050_I2C_TIMEOUT) < 0)
        return -1;
    if (mpu6050_aux_enable(!enable))
        return -1;
    return 0;
}

int mpu6050_low_power_accelerometer_mode_get(void)
{
    uint8_t pwr_mgmt[2] = {0};
    if (iic_master_read(MPU6050_I2C_PORT, MPU6050_I2C_ADDR, MPUR_PWR_MGMT1, pwr_mgmt, 2, MPU6050_I2C_TIMEOUT) < 0)
        return -1;
    pwr_mgmt[0] &= (1 << MPUR_PWR1_SLEEP_BIT) | (1 << MPUR_PWR1_CYCLE_BIT) | (1 << MPUR_PWR1_TEMP_DIS_BIT);
    pwr_mgmt[1] &= MPUR_PWR2_STBY_XYZA_BITS | MPUR_PWR2_STBY_XYZG_BITS;
    return pwr_mgmt[0] == ((1 << MPUR_PWR1_CYCLE_BIT) | (1 << MPUR_PWR1_TEMP_DIS_BIT)) && pwr_mgmt[1] == MPUR_PWR2_STBY_XYZG_BITS;
}

int mpu6050_acceleration(int16_t *x, int16_t *y, int16_t *z)
{
    if (MPU_STATE_MPU_SERVICE != _state)
        return -1;
    uint8_t buffer[6] = {0};
    if (iic_master_read(MPU6050_I2C_PORT, MPU6050_I2C_ADDR, MPUR_ACCEL_XOUT_H, buffer, 6, MPU6050_I2C_TIMEOUT) < 0)
        return -1;
    *x = buffer[0] << 8 | buffer[1];
    *y = buffer[2] << 8 | buffer[3];
    *z = buffer[4] << 8 | buffer[5];
    return 0;
}

int mpu6050_rotation(int16_t *x, int16_t *y, int16_t *z)
{
    if (MPU_STATE_MPU_SERVICE != _state)
        return -1;
    uint8_t buffer[6] = {0};
    if (iic_master_read(MPU6050_I2C_PORT, MPU6050_I2C_ADDR, MPUR_GYRO_XOUT_H, buffer, 6, MPU6050_I2C_TIMEOUT) < 0)
        return -1;
    *x = buffer[0] << 8 | buffer[1];
    *y = buffer[2] << 8 | buffer[3];
    *z = buffer[4] << 8 | buffer[5];
    return 0;
}

int mpu6050_temperature(int16_t *temp)
{
    if (MPU_STATE_MPU_SERVICE != _state)
        return -1;
    uint8_t buffer[2] = {0};
    if (iic_master_read(MPU6050_I2C_PORT, MPU6050_I2C_ADDR, MPUR_TEMP_OUT_H, buffer, 2, MPU6050_I2C_TIMEOUT) < 0)
        return -1;
    *temp = buffer[0] << 8 | buffer[1];
    return 0;
}

int mpu6050_motion(int16_t *accel, int16_t *gyro, int16_t *temp)
{
    if (MPU_STATE_MPU_SERVICE != _state)
        return -1;
    uint8_t buffer[14] = {0};
    if (iic_master_read(MPU6050_I2C_PORT, MPU6050_I2C_ADDR, MPUR_ACCEL_XOUT_H, buffer, 14, MPU6050_I2C_TIMEOUT) < 0)
        return -1;
    accel[0] = buffer[0] << 8 | buffer[1];
    accel[1] = buffer[2] << 8 | buffer[3];
    accel[2] = buffer[4] << 8 | buffer[5];
    *temp = buffer[6] << 8 | buffer[7];
    gyro[0] = buffer[8] << 8 | buffer[9];
    gyro[1] = buffer[10] << 8 | buffer[11];
    gyro[2] = buffer[12] << 8 | buffer[13];
    return 0;
}

int mpu6050_fifo_size(void)
{
    if (MPU_STATE_MPU_SERVICE != _state)
        return -1;
    uint8_t buffer[2] = {0};
    if (iic_master_read(MPU6050_I2C_PORT, MPU6050_I2C_ADDR, MPUR_FIFO_COUNT_H, buffer, 2, MPU6050_I2C_TIMEOUT) < 0)
    {
        SigmaLogError(0, 0, "MPUR_FIFO_COUNT_H failed.");
        return -1;
    }
    return buffer[0] << 8 | buffer[1];
}

int mpu6050_biases(uint8_t accelFS, uint8_t gyroFS, int16_t* accelBias, int16_t* gyroBias, bool selftest)
{
    const uint16_t kSampleRate = 1000;
    const uint8_t kDLPF = DLPF_188HZ;
    const size_t kPacketSize = 12;
    uint8_t buffer[12] = {0};
    
    if (mpu6050_sample_rate(kSampleRate) < 0)
    {
        SigmaLogError(0, 0, "sample rate failed.");
        return -1;
    }
    if (iic_master_bwrite(MPU6050_I2C_PORT, MPU6050_I2C_ADDR, MPUR_CONFIG, MPUR_CONFIG_DLPF_CFG_BIT, kDLPF, MPUR_CONFIG_DLPF_CFG_LENGTH, MPU6050_I2C_TIMEOUT) < 0)
    {
        SigmaLogError(0, 0, "digital low pass filter failed.");
        return -1;
    }
    if (iic_master_bwrite(MPU6050_I2C_PORT, MPU6050_I2C_ADDR, MPUR_ACCEL_CONFIG, MPUR_ACONFIG_FS_SEL_BIT, accelFS, MPUR_ACONFIG_FS_SEL_LENGTH, MPU6050_I2C_TIMEOUT) < 0)
    {
        SigmaLogError(0, 0, "accel full scale failed.");
        return -1;
    }
    if (iic_master_bwrite(MPU6050_I2C_PORT, MPU6050_I2C_ADDR, MPUR_GYRO_CONFIG, MPUR_GCONFIG_FS_SEL_BIT, gyroFS, MPUR_GCONFIG_FS_SEL_LENGTH, MPU6050_I2C_TIMEOUT) < 0)
    {
        SigmaLogError(0, 0, "gyro full scale failed.");
        return -1;
    }
    if (selftest)
    {
        if (iic_master_bwrite(MPU6050_I2C_PORT, MPU6050_I2C_ADDR, MPUR_ACCEL_CONFIG, MPUR_ACONFIG_XA_ST_BIT, 0x07, 3, MPU6050_I2C_TIMEOUT) < 0)
        {
            SigmaLogError(0, 0, "failed.");
            return -1;
        }
        if (iic_master_bwrite(MPU6050_I2C_PORT, MPU6050_I2C_ADDR, MPUR_GYRO_CONFIG, MPUR_GCONFIG_XG_ST_BIT, 0x7, 3, MPU6050_I2C_TIMEOUT) < 0)
        {
            SigmaLogError(0, 0, "failed.");
            return -1;
        }
    }
    os_sleep(200);

    if (iic_master_bset(MPU6050_I2C_PORT, MPU6050_I2C_ADDR, MPUR_USER_CTRL, MPUR_USERCTRL_FIFO_RESET_BIT, MPU6050_I2C_TIMEOUT) < 0)
    {
        SigmaLogError(0, 0, "fifo reset failed.");
        return -1;
    }
    os_sleep(100);

    int fifoCount = mpu6050_fifo_size();
    if (fifoCount < 0)
    {
        SigmaLogError(0, 0, "mpu6050_fifo_size failed");
        return -1;
    }
    const int packetCount = fifoCount / kPacketSize;
    const int overrunCount = fifoCount - (packetCount * kPacketSize);
    if (overrunCount > 0)
    {
        if (iic_master_read(MPU6050_I2C_PORT, MPU6050_I2C_ADDR, MPUR_FIFO_R_W, buffer, overrunCount, MPU6050_I2C_TIMEOUT) < 0)
        {
            SigmaLogError(0, 0, "MPUR_FIFO_R_W failed.");
            return -1;
        }
    }
    
    int accelAvg[3] = {0}, gyroAvg[3] = {0};
    for (int i = 0; i < packetCount; i++)
    {
        if (iic_master_read(MPU6050_I2C_PORT, MPU6050_I2C_ADDR, MPUR_FIFO_R_W, buffer, kPacketSize, MPU6050_I2C_TIMEOUT) < 0)
        {
            SigmaLogError(0, 0, "MPUR_FIFO_R_W failed.");
            return -1;
        }
        int16_t accelCur[3], gyroCur[3];
        accelCur[0] = (buffer[0] << 8) | buffer[1];
        accelCur[1] = (buffer[2] << 8) | buffer[3];
        accelCur[2] = (buffer[4] << 8) | buffer[5];
        gyroCur[0]  = (buffer[6] << 8) | buffer[7];
        gyroCur[1]  = (buffer[8] << 8) | buffer[9];
        gyroCur[2]  = (buffer[10] << 8) | buffer[11];

        accelAvg[0] += accelCur[0];
        accelAvg[1] += accelCur[1];
        accelAvg[2] += accelCur[2];

        gyroAvg[0] += gyroCur[0];
        gyroAvg[1] += gyroCur[1];
        gyroAvg[2] += gyroCur[2];
    }
    accelAvg[0] /= packetCount;
    accelAvg[1] /= packetCount;
    accelAvg[2] /= packetCount;
    gyroAvg[0] /= packetCount;
    gyroAvg[1] /= packetCount;
    gyroAvg[2] /= packetCount;
    
    const uint16_t gravityLSB = INT16_MAX >> (accelFS + 1);
    accelAvg[2] -= gravityLSB;
    for (int i = 0; i < 3; i++)
    {
        accelBias[i] = (int16_t) accelAvg[i];
        gyroBias[i]  = (int16_t) gyroAvg[i];
    }
    
    if (mpu6050_sample_rate(MPU6050_SAMPLE_RATE) < 0)
    {
        SigmaLogError(0, 0, "sample rate failed.");
        return -1;
    }
    if (iic_master_bwrite(MPU6050_I2C_PORT, MPU6050_I2C_ADDR, MPUR_CONFIG, MPUR_CONFIG_DLPF_CFG_BIT, MPU6050_DIGITAL_LOW_PASS_FILTER, MPUR_CONFIG_DLPF_CFG_LENGTH, MPU6050_I2C_TIMEOUT) < 0)
    {
        SigmaLogError(0, 0, "digital low pass filter failed.");
        return -1;
    }
    if (iic_master_bwrite(MPU6050_I2C_PORT, MPU6050_I2C_ADDR, MPUR_ACCEL_CONFIG, MPUR_ACONFIG_FS_SEL_BIT, MPU6050_ACCEL_FULL_SCALE, MPUR_ACONFIG_FS_SEL_LENGTH, MPU6050_I2C_TIMEOUT) < 0)
    {
        SigmaLogError(0, 0, "accel full scale failed.");
        return -1;
    }
    if (iic_master_bwrite(MPU6050_I2C_PORT, MPU6050_I2C_ADDR, MPUR_GYRO_CONFIG, MPUR_GCONFIG_FS_SEL_BIT, MPU6050_GYRO_FULL_SCALE, MPUR_GCONFIG_FS_SEL_LENGTH, MPU6050_I2C_TIMEOUT) < 0)
    {
        SigmaLogError(0, 0, "gyro full scale failed.");
        return -1;
    }
    
    uint8_t setting = ~0x07;
    if (iic_master_write(MPU6050_I2C_PORT, MPU6050_I2C_ADDR, MPUR_FIFO_EN, &setting, 1, MPU6050_I2C_TIMEOUT) < 0)
    {
        SigmaLogError(0, 0, "fifo failed.");
        return -1;
    }
    if (iic_master_bclear(MPU6050_I2C_PORT, MPU6050_I2C_ADDR, MPUR_I2C_MST_CTRL, MPUR_I2CMST_CTRL_SLV_3_FIFO_EN_BIT, MPU6050_I2C_TIMEOUT) < 0)
    {
        SigmaLogError(0, 0, "fifo failed.");
        return -1;
    }
    return 0;
}

int mpu6050_gyro_self_test(int16_t *regularBias, int16_t *selfTestBias)
{
    const uint8_t kGyroFS = GYRO_FS_250DPS;

    const float kMaxVariation = .14f;
    const float kMinDPS = 10.f, kMaxDPS = 105.f;

    float regularBiasDPS[3] = {0};
    gyro_degree_per_second(regularBias, kGyroFS, regularBiasDPS);
    float selfTestBiasDPS[3] = {0};
    gyro_degree_per_second(selfTestBias, kGyroFS, selfTestBiasDPS);

    SigmaLogAction(0, 0, "regularBias: %+d %+d %+d | regularBiasDPS: %+.2f %+.2f %+.2f", 
            regularBias[0], regularBias[1], regularBias[2], 
            regularBiasDPS[0], regularBiasDPS[1], regularBiasDPS[1]);
    SigmaLogAction(0, 0, "selfTestBias: %+d %+d %+d | selfTestBiasDPS: %+.2f %+.2f %+.2f", 
            selfTestBias[0], selfTestBias[1], selfTestBias[2], 
            selfTestBiasDPS[0], selfTestBiasDPS[1], selfTestBiasDPS[2]);

    uint8_t shiftCode[3];
    if (iic_master_read(MPU6050_I2C_PORT, MPU6050_I2C_ADDR, MPUR_SELF_TEST_X, shiftCode, 3, MPU6050_I2C_TIMEOUT) < 0)
        return -1;
    shiftCode[0] = shiftCode[0] & 0x1F;
    shiftCode[1] = shiftCode[1] & 0x1F;
    shiftCode[2] = shiftCode[2] & 0x1F;
    SigmaLogAction(0, 0, "shiftCode: %+d %+d %+d", shiftCode[0], shiftCode[1], shiftCode[2]);

    float shiftProduction[3] = {0};
    for (int i = 0; i < 3; i++)
    {
        if (shiftCode[i] != 0)
        {
            shiftProduction[i] = 3275.f / gyro_sensitivity(kGyroFS);  // should yield 25
            while (--shiftCode[i])
                shiftProduction[i] *= 1.046f;
        }
    }
    SigmaLogAction(0, 0, "shiftProduction: %+.2f %+.2f %+.2f", 
        shiftProduction[0], shiftProduction[1], shiftProduction[2]);

    int result              = 0;
    float shiftResponse[3]  = {0};
    float shiftVariation[3] = {0};
    for (int i = 0; i < 3; i++)
    {
        shiftResponse[i] = fabs(selfTestBiasDPS[i] - regularBiasDPS[i]);
        if (shiftProduction[i] != 0)
        {
            shiftVariation[i] = shiftResponse[i] / shiftProduction[i] - 1;
            if (fabs(shiftVariation[i]) > kMaxVariation) 
                result |= 1 << i;
        }
        else if (shiftResponse[i] < kMinDPS || shiftResponse[i] > kMaxDPS)
        {
            result |= 1 << i;
        }
    }
    SigmaLogAction(0, 0, "shiftResponse: %+.2f %+.2f %+.2f", 
        shiftResponse[0], shiftResponse[1], shiftResponse[2]);

    SigmaLogAction(0, 0, "shiftVariation: %+.2f %+.2f %+.2f", 
        shiftVariation[0], shiftVariation[1], shiftVariation[2]);

    SigmaLogAction(0, 0, "Gyro self-test: [X=%s] [Y=%s] [Z=%s]",
        ((result & 0x1) ? "FAIL" : "OK"),
        ((result & 0x2) ? "FAIL" : "OK"),
        ((result & 0x4) ? "FAIL" : "OK"));
    return result;
}

int mpu6050_accel_self_test(int16_t *regularBias, int16_t *selfTestBias)
{
    const uint8_t kAccelFS = ACCEL_FS_16G;

    const float kMaxVariation = .14f;
    const float kMinGravity = .3f, kMaxGravity = .95f;

    float regularBiasGravity[3] = {0};
    accel_gravity(regularBias, kAccelFS, regularBiasGravity);

    float selfTestBiasGravity[3] = {0};
    accel_gravity(selfTestBias, kAccelFS, selfTestBiasGravity);

    SigmaLogAction(0, 0, "regularBias: %+d %+d %+d | regularBiasGravity: %+.2f %+.2f %+.2f", 
        regularBias[0], regularBias[1], regularBias[2], 
        regularBiasGravity[0], regularBiasGravity[1], regularBiasGravity[2]);
    SigmaLogAction(0, 0, "selfTestBias: %+d %+d %+d | selfTestBiasGravity: %+.2f %+.2f %+.2f", 
        selfTestBias[0], selfTestBias[1], selfTestBias[2], 
        selfTestBiasGravity[0], selfTestBiasGravity[1], selfTestBiasGravity[2]);

    uint8_t shiftCode[4];
    if (iic_master_read(MPU6050_I2C_PORT, MPU6050_I2C_ADDR, MPUR_SELF_TEST_X, shiftCode, 4, MPU6050_I2C_TIMEOUT) < 0)
        return -1;
    shiftCode[0] = ((shiftCode[0] & 0xE0) >> 3) | ((shiftCode[3] & 0x30) >> 4);
    shiftCode[1] = ((shiftCode[1] & 0xE0) >> 3) | ((shiftCode[3] & 0x0C) >> 2);
    shiftCode[2] = ((shiftCode[2] & 0xE0) >> 3) | (shiftCode[3] & 0x03);
    SigmaLogAction(0, 0, "shiftCode: %+d %+d %+d", shiftCode[0], shiftCode[1], shiftCode[2]);

    float shiftProduction[3] = {0};
    for (int i = 0; i < 3; i++)
    {
        if (shiftCode[i] != 0)
        {
            shiftProduction[i] = 0.34f;
            while (--shiftCode[i])
                shiftProduction[i] *= 1.034f;
        }
    }
    SigmaLogAction(0, 0, "shiftProduction: %+.2f %+.2f %+.2f", 
        shiftProduction[0], shiftProduction[1], shiftProduction[2]);

    int result              = 0;
    float shiftResponse[3]  = {0};
    float shiftVariation[3] = {0};
    for (int i = 0; i < 3; i++)
    {
        shiftResponse[i] = fabs(selfTestBiasGravity[i] - regularBiasGravity[i]);
        if (shiftProduction[i] != 0)
        {
            shiftVariation[i] = shiftResponse[i] / shiftProduction[i] - 1;
            if (fabs(shiftVariation[i]) > kMaxVariation) 
                result |= 1 << i;
        }
        else if (shiftResponse[i] < kMinGravity || shiftResponse[i] > kMaxGravity)
        {
            result |= 1 << i;
        }
    }
    SigmaLogAction(0, 0, "shiftResponse: %+.2f %+.2f %+.2f", 
        shiftResponse[0], shiftResponse[1], shiftResponse[2]);
    SigmaLogAction(0, 0, "shiftVariation: %+.2f %+.2f %+.2f", 
        shiftVariation[0], shiftVariation[1], shiftVariation[2]);

    SigmaLogAction(0, 0, "Accel self-test: [X=%s] [Y=%s] [Z=%s]",
        ((result & 0x1) ? "FAIL" : "OK"),
        ((result & 0x2) ? "FAIL" : "OK"),
        ((result & 0x4) ? "FAIL" : "OK"));
    return result;
}

int mpu6050_self_test(void)
{
    const uint8_t kAccelFS = ACCEL_FS_16G;
    const uint8_t kGyroFS = GYRO_FS_250DPS;
    int16_t gyroRegBias[3], accelRegBias[3];
    int16_t gyroSTBias[3], accelSTBias[3];
    if (mpu6050_biases(kAccelFS, kGyroFS, accelRegBias, gyroRegBias, false) < 0)
    {
        SigmaLogError(0, 0, "biases failed.");
        return -1;
    }
    if (mpu6050_biases(kAccelFS, kGyroFS, accelSTBias, gyroSTBias, true) < 0)
    {
        SigmaLogError(0, 0, "biases failed.");
        return -1;
    }
    int accelST, gyroST;
    if ((accelST = mpu6050_accel_self_test(accelRegBias, accelSTBias)) < 0)
    {
        SigmaLogError(0, 0, "mpu6050_accel_self_test failed.");
        return -1;
    }
    if ((gyroST = mpu6050_gyro_self_test(gyroRegBias, gyroSTBias)) < 0)
    {
        SigmaLogError(0, 0, "mpu6050_gyro_self_test failed.");
        return -1;
    }
    int result = 0;
    if (accelST != 0)
        result |= 1;
    if (gyroST != 0)
        result |= 2;
    return result;
}

int mpu6050_gyro_degree(const int16_t *in, float *out)
{
    return gyro_degree_per_second(in, MPU6050_GYRO_FULL_SCALE, out);
}

int mpu6050_accel_gravity(const int16_t *in, float out)
{
    return accel_gravity(in, MPU6050_ACCEL_FULL_SCALE, out);
}
