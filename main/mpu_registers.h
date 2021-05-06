#ifndef _MPU_REGISTERS_H_
#define _MPU_REGISTERS_H_

/*******************************************************************************
 * MPU commom registers for all models
 ******************************************************************************/
const uint8_t MPUR_XG_OFFSET_H = (0x13);
const uint8_t MPUR_XG_OFFSET_L = (0x14);
const uint8_t MPUR_YG_OFFSET_H = (0x15);
const uint8_t MPUR_YG_OFFSET_L = (0x16);
const uint8_t MPUR_ZG_OFFSET_H = (0x17);
const uint8_t MPUR_ZG_OFFSET_L = (0x18);
const uint8_t MPUR_SMPLRT_DIV  = (0x19);  // [7:0]
//------------------------------------------------------------------------------
const uint8_t MPUR_CONFIG                     = (0x1A);
const uint8_t MPUR_CONFIG_FIFO_MODE_BIT       = (6);
const uint8_t MPUR_CONFIG_EXT_SYNC_SET_BIT    = (5);  // [5:3]
const uint8_t MPUR_CONFIG_EXT_SYNC_SET_LENGTH = (3);
const uint8_t MPUR_CONFIG_DLPF_CFG_BIT        = (2);  // [2:0]
const uint8_t MPUR_CONFIG_DLPF_CFG_LENGTH     = (3);
//------------------------------------------------------------------------------
const uint8_t MPUR_GYRO_CONFIG              = (0x1B);
const uint8_t MPUR_GCONFIG_XG_ST_BIT        = (7);
const uint8_t MPUR_GCONFIG_YG_ST_BIT        = (6);
const uint8_t MPUR_GCONFIG_ZG_ST_BIT        = (5);
const uint8_t MPUR_GCONFIG_FS_SEL_BIT       = (4);  // [4:3]
const uint8_t MPUR_GCONFIG_FS_SEL_LENGTH    = (2);
const uint8_t MPUR_GCONFIG_FCHOICE_B        = (1);  // [1:0]
const uint8_t MPUR_GCONFIG_FCHOICE_B_LENGTH = (2);
//------------------------------------------------------------------------------
const uint8_t MPUR_ACCEL_CONFIG          = (0x1C);
const uint8_t MPUR_ACONFIG_XA_ST_BIT     = (7);
const uint8_t MPUR_ACONFIG_YA_ST_BIT     = (6);
const uint8_t MPUR_ACONFIG_ZA_ST_BIT     = (5);
const uint8_t MPUR_ACONFIG_FS_SEL_BIT    = (4);  // [4:3]
const uint8_t MPUR_ACONFIG_FS_SEL_LENGTH = (2);
const uint8_t MPUR_ACONFIG_HPF_BIT       = (2);  // [2:0]
const uint8_t MPUR_ACONFIG_HPF_LENGTH    = (3);
//------------------------------------------------------------------------------
const uint8_t MPUR_FF_THR       = (0x1D);
const uint8_t MPUR_FF_DUR       = (0x1E);
const uint8_t MPUR_MOTION_THR   = (0x1F);  // [7:0] // MPU9250_REG_WOM_THR
const uint8_t MPUR_MOTION_DUR   = (0x20);
const uint8_t MPUR_ZRMOTION_THR = (0x21);
const uint8_t MPUR_ZRMOTION_DUR = (0x22);
//------------------------------------------------------------------------------
const uint8_t MPUR_FIFO_EN           = (0x23);
const uint8_t MPUR_FIFO_TEMP_EN_BIT  = (7);
const uint8_t MPUR_FIFO_XGYRO_EN_BIT = (6);
const uint8_t MPUR_FIFO_YGYRO_EN_BIT = (5);
const uint8_t MPUR_FIFO_ZGYRO_EN_BIT = (4);
const uint8_t MPUR_FIFO_ACCEL_EN_BIT = (3);
const uint8_t MPUR_FIFO_SLV_2_EN_BIT = (2);
const uint8_t MPUR_FIFO_SLV_1_EN_BIT = (1);
const uint8_t MPUR_FIFO_SLV_0_EN_BIT = (0);
//------------------------------------------------------------------------------
const uint8_t MPUR_I2C_MST_CTRL                  = (0x24);
const uint8_t MPUR_I2CMST_CTRL_MULT_EN_BIT       = (7);
const uint8_t MPUR_I2CMST_CTRL_WAIT_FOR_ES_BIT   = (6);
const uint8_t MPUR_I2CMST_CTRL_SLV_3_FIFO_EN_BIT = (5);
const uint8_t MPUR_I2CMST_CTRL_P_NSR_BIT         = (4);
const uint8_t MPUR_I2CMST_CTRL_CLOCK_BIT         = (3);  // [3:0]
const uint8_t MPUR_I2CMST_CTRL_CLOCK_LENGTH      = (4);
//------------------------------------------------------------------------------
const uint8_t MPUR_I2C_SLV0_ADDR     = (0x25);
const uint8_t MPUR_I2C_SLV_RNW_BIT   = (7);  // same for all I2C_SLV registers
const uint8_t MPUR_I2C_SLV_ID_BIT    = (6);  // [6:0]
const uint8_t MPUR_I2C_SLV_ID_LENGTH = (7);
//------------------------------------------------------------------------------
const uint8_t MPUR_I2C_SLV0_REG = (0x26);  // [7:0]
//------------------------------------------------------------------------------
const uint8_t MPUR_I2C_SLV0_CTRL       = (0x27);
const uint8_t MPUR_I2C_SLV_EN_BIT      = (7);  // same for all I2C_SLV registers
const uint8_t MPUR_I2C_SLV_BYTE_SW_BIT = (6);
const uint8_t MPUR_I2C_SLV_REG_DIS_BIT = (5);
const uint8_t MPUR_I2C_SLV_GRP_BIT     = (4);
const uint8_t MPUR_I2C_SLV_LEN_BIT     = (3);  // [3:0]
const uint8_t MPUR_I2C_SLV_LEN_LENGTH  = (4);
//------------------------------------------------------------------------------
const uint8_t MPUR_I2C_SLV1_ADDR = (0x28);  // see SLV0 for bit defines
const uint8_t MPUR_I2C_SLV1_REG  = (0x29);
const uint8_t MPUR_I2C_SLV1_CTRL = (0x2A);
const uint8_t MPUR_I2C_SLV2_ADDR = (0x2B);  // see SLV0 for bit defines
const uint8_t MPUR_I2C_SLV2_REG  = (0x2C);
const uint8_t MPUR_I2C_SLV2_CTRL = (0x2D);
const uint8_t MPUR_I2C_SLV3_ADDR = (0x2E);  // see SLV0 for bit defines
const uint8_t MPUR_I2C_SLV3_REG  = (0x2F);
const uint8_t MPUR_I2C_SLV3_CTRL = (0x30);
const uint8_t MPUR_I2C_SLV4_ADDR = (0x31);  // see SLV0 for bit defines
const uint8_t MPUR_I2C_SLV4_REG  = (0x32);
const uint8_t MPUR_I2C_SLV4_DO   = (0x33);  // [7:0]
//------------------------------------------------------------------------------
const uint8_t MPUR_I2C_SLV4_CTRL             = (0x34);
const uint8_t MPUR_I2C_SLV4_EN_BIT           = (7);
const uint8_t MPUR_I2C_SLV4_DONE_INT_BIT     = (6);
const uint8_t MPUR_I2C_SLV4_REG_DIS_BIT      = (5);
const uint8_t MPUR_I2C_SLV4_MST_DELAY_BIT    = (4);  // [4:0]
const uint8_t MPUR_I2C_SLV4_MST_DELAY_LENGTH = (5);
//------------------------------------------------------------------------------
const uint8_t MPUR_I2C_SLV4_DI = (0x35);  // [7:0]
//------------------------------------------------------------------------------
const uint8_t MPUR_I2C_MST_STATUS               = (0x36);
const uint8_t MPUR_I2CMST_STAT_PASS_THROUGH_BIT = (7);
const uint8_t MPUR_I2CMST_STAT_SLV4_DONE_BIT    = (6);
const uint8_t MPUR_I2CMST_STAT_LOST_ARB_BIT     = (5);
const uint8_t MPUR_I2CMST_STAT_SLV4_NACK_BIT    = (4);
const uint8_t MPUR_I2CMST_STAT_SLV3_NACK_BIT    = (3);
const uint8_t MPUR_I2CMST_STAT_SLV2_NACK_BIT    = (2);
const uint8_t MPUR_I2CMST_STAT_SLV1_NACK_BIT    = (1);
const uint8_t MPUR_I2CMST_STAT_SLV0_NACK_BIT    = (0);
//------------------------------------------------------------------------------
const uint8_t MPUR_INT_PIN_CONFIG                = (0x37);
const uint8_t MPUR_INT_CFG_LEVEL_BIT             = (7);
const uint8_t MPUR_INT_CFG_OPEN_BIT              = (6);
const uint8_t MPUR_INT_CFG_LATCH_EN_BIT          = (5);
const uint8_t MPUR_INT_CFG_ANYRD_2CLEAR_BIT      = (4);
const uint8_t MPUR_INT_CFG_FSYNC_LEVEL_BIT       = (3);
const uint8_t MPUR_INT_CFG_FSYNC_INT_MODE_EN_BIT = (2);
const uint8_t MPUR_INT_CFG_I2C_BYPASS_EN_BIT     = (1);
const uint8_t MPUR_INT_CFG_CLOCKOUT_EN_BIT       = (0);
//------------------------------------------------------------------------------
const uint8_t MPUR_INT_ENABLE                   = (0x38);
const uint8_t MPUR_INT_ENABLE_FREEFALL_BIT      = (7);
const uint8_t MPUR_INT_ENABLE_MOTION_BIT        = (6);
const uint8_t MPUR_INT_ENABLE_ZEROMOT_BIT       = (5);
const uint8_t MPUR_INT_ENABLE_FIFO_OFLOW_BIT    = (4);
const uint8_t MPUR_INT_ENABLE_I2C_MST_FSYNC_BIT = (3);
const uint8_t MPUR_INT_ENABLE_PLL_RDY_BIT       = (2);
const uint8_t MPUR_INT_ENABLE_DMP_RDY_BIT       = (1);
const uint8_t MPUR_INT_ENABLE_RAW_DATA_RDY_BIT  = (0);
//------------------------------------------------------------------------------
const uint8_t MPUR_DMP_INT_STATUS   = (0x39);
const uint8_t MPUR_DMP_INT_STATUS_0 = (0);
const uint8_t MPUR_DMP_INT_STATUS_1 = (1);
const uint8_t MPUR_DMP_INT_STATUS_2 = (2);
const uint8_t MPUR_DMP_INT_STATUS_3 = (3);
const uint8_t MPUR_DMP_INT_STATUS_4 = (4);
const uint8_t MPUR_DMP_INT_STATUS_5 = (5);
//------------------------------------------------------------------------------
const uint8_t MPUR_INT_STATUS                  = (0x3A);
const uint8_t MPUR_INT_STATUS_FREEFALL_BIT     = (7);
const uint8_t MPUR_INT_STATUS_MOTION_BIT       = (6);
const uint8_t MPUR_INT_STATUS_ZEROMOT_BIT      = (5);
const uint8_t MPUR_INT_STATUS_FIFO_OFLOW_BIT   = (4);
const uint8_t MPUR_INT_STATUS_I2C_MST_BIT      = (3);
const uint8_t MPUR_INT_STATUS_PLL_RDY_BIT      = (2);
const uint8_t MPUR_INT_STATUS_DMP_RDY_BIT      = (1);
const uint8_t MPUR_INT_STATUS_RAW_DATA_RDY_BIT = (0);
//------------------------------------------------------------------------------
const uint8_t MPUR_ACCEL_XOUT_H     = (0x3B);  // [15:0]
const uint8_t MPUR_ACCEL_XOUT_L     = (0x3C);
const uint8_t MPUR_ACCEL_YOUT_H     = (0x3D);  // [15:0]
const uint8_t MPUR_ACCEL_YOUT_L     = (0x3E);
const uint8_t MPUR_ACCEL_ZOUT_H     = (0x3F);  // [15:0]
const uint8_t MPUR_ACCEL_ZOUT_L     = (0x40);
const uint8_t MPUR_TEMP_OUT_H       = (0x41);  // [15:0]
const uint8_t MPUR_TEMP_OUT_L       = (0x42);
const uint8_t MPUR_GYRO_XOUT_H      = (0x43);  // [15:0]
const uint8_t MPUR_GYRO_XOUT_L      = (0x44);
const uint8_t MPUR_GYRO_YOUT_H      = (0x45);  // [15:0]
const uint8_t MPUR_GYRO_YOUT_L      = (0x46);
const uint8_t MPUR_GYRO_ZOUT_H      = (0x47);  // [15:0]
const uint8_t MPUR_GYRO_ZOUT_L      = (0x48);
const uint8_t MPUR_EXT_SENS_DATA_00 = (0x49);  // Stores data read from Slave 0, 1, 2, and 3
const uint8_t MPUR_EXT_SENS_DATA_01 = (0x4A);
const uint8_t MPUR_EXT_SENS_DATA_02 = (0x4B);
const uint8_t MPUR_EXT_SENS_DATA_03 = (0x4C);
const uint8_t MPUR_EXT_SENS_DATA_04 = (0x4D);
const uint8_t MPUR_EXT_SENS_DATA_05 = (0x4E);
const uint8_t MPUR_EXT_SENS_DATA_06 = (0x4F);
const uint8_t MPUR_EXT_SENS_DATA_07 = (0x50);
const uint8_t MPUR_EXT_SENS_DATA_08 = (0x51);
const uint8_t MPUR_EXT_SENS_DATA_09 = (0x52);
const uint8_t MPUR_EXT_SENS_DATA_10 = (0x53);
const uint8_t MPUR_EXT_SENS_DATA_11 = (0x54);
const uint8_t MPUR_EXT_SENS_DATA_12 = (0x55);
const uint8_t MPUR_EXT_SENS_DATA_13 = (0x56);
const uint8_t MPUR_EXT_SENS_DATA_14 = (0x57);
const uint8_t MPUR_EXT_SENS_DATA_15 = (0x58);
const uint8_t MPUR_EXT_SENS_DATA_16 = (0x59);
const uint8_t MPUR_EXT_SENS_DATA_17 = (0x5A);
const uint8_t MPUR_EXT_SENS_DATA_18 = (0x5B);
const uint8_t MPUR_EXT_SENS_DATA_19 = (0x5C);
const uint8_t MPUR_EXT_SENS_DATA_20 = (0x5D);
const uint8_t MPUR_EXT_SENS_DATA_21 = (0x5E);
const uint8_t MPUR_EXT_SENS_DATA_22 = (0x5F);
const uint8_t MPUR_EXT_SENS_DATA_23 = (0x60);
const uint8_t MPUR_I2C_SLV0_DO      = (0x63);
const uint8_t MPUR_I2C_SLV1_DO      = (0x64);
const uint8_t MPUR_I2C_SLV2_DO      = (0x65);
const uint8_t MPUR_I2C_SLV3_DO      = (0x66);
//------------------------------------------------------------------------------
const uint8_t MPUR_I2C_MST_DELAY_CRTL       = (0x67);
const uint8_t MPUR_I2CMST_DLY_ES_SHADOW_BIT = (7);
const uint8_t MPUR_I2CMST_DLY_SLV4_EN_BIT   = (4);
const uint8_t MPUR_I2CMST_DLY_SLV3_EN_BIT   = (3);
const uint8_t MPUR_I2CMST_DLY_SLV2_EN_BIT   = (2);
const uint8_t MPUR_I2CMST_DLY_SLV1_EN_BIT   = (1);
const uint8_t MPUR_I2CMST_DLY_SLV0_EN_BIT   = (0);
//------------------------------------------------------------------------------
const uint8_t MPUR_SIGNAL_PATH_RESET   = (0x68);
const uint8_t MPUR_SPATH_GYRO_RST_BIT  = (2);
const uint8_t MPUR_SPATH_ACCEL_RST_BIT = (1);
const uint8_t MPUR_SPATH_TEMP_RST_BIT  = (0);
//------------------------------------------------------------------------------
const uint8_t MPUR_USER_CTRL                   = (0x6A);
const uint8_t MPUR_USERCTRL_DMP_EN_BIT         = (7);
const uint8_t MPUR_USERCTRL_FIFO_EN_BIT        = (6);
const uint8_t MPUR_USERCTRL_I2C_MST_EN_BIT     = (5);
const uint8_t MPUR_USERCTRL_I2C_IF_DIS_BIT     = (4);
const uint8_t MPUR_USERCTRL_DMP_RESET_BIT      = (3);
const uint8_t MPUR_USERCTRL_FIFO_RESET_BIT     = (2);
const uint8_t MPUR_USERCTRL_I2C_MST_RESET_BIT  = (1);
const uint8_t MPUR_USERCTRL_SIG_COND_RESET_BIT = (0);
//------------------------------------------------------------------------------
const uint8_t MPUR_PWR_MGMT1             = (0x6B);
const uint8_t MPUR_PWR1_DEVICE_RESET_BIT = (7);
const uint8_t MPUR_PWR1_SLEEP_BIT        = (6);
const uint8_t MPUR_PWR1_CYCLE_BIT        = (5);
const uint8_t MPUR_PWR1_GYRO_STANDBY_BIT = (4);
const uint8_t MPUR_PWR1_TEMP_DIS_BIT     = (3);
const uint8_t MPUR_PWR1_CLKSEL_BIT       = (2);
const uint8_t MPUR_PWR1_CLKSEL_LENGTH    = (3);
//------------------------------------------------------------------------------
const uint8_t MPUR_PWR_MGMT2                = (0x6C);
const uint8_t MPUR_PWR2_LP_WAKE_CTRL_BIT    = (7);
const uint8_t MPUR_PWR2_LP_WAKE_CTRL_LENGTH = (2);
const uint8_t MPUR_PWR2_STBY_XA_BIT         = (5);
const uint8_t MPUR_PWR2_STBY_YA_BIT         = (4);
const uint8_t MPUR_PWR2_STBY_ZA_BIT         = (3);
const uint8_t MPUR_PWR2_STBY_XG_BIT         = (2);
const uint8_t MPUR_PWR2_STBY_YG_BIT         = (1);
const uint8_t MPUR_PWR2_STBY_ZG_BIT         = (0);
const uint8_t MPUR_PWR2_STBY_XYZA_BITS      = (1 << MPUR_PWR2_STBY_XA_BIT | 1 << MPUR_PWR2_STBY_YA_BIT | 1 << MPUR_PWR2_STBY_ZA_BIT);
const uint8_t MPUR_PWR2_STBY_XYZG_BITS      = (1 << MPUR_PWR2_STBY_XG_BIT | 1 << MPUR_PWR2_STBY_YG_BIT | 1 << MPUR_PWR2_STBY_ZG_BIT);
//------------------------------------------------------------------------------
const uint8_t MPUR_BANK_SEL                  = (0x6D);
const uint8_t MPUR_BANKSEL_PRFTCH_EN_BIT     = (6);
const uint8_t MPUR_BANKSEL_CFG_USER_BANK_BIT = (5);
const uint8_t MPUR_BANKSEL_MEM_SEL_BIT       = (4);
const uint8_t MPUR_BANKSEL_MEM_SEL_LENGTH    = (5);
//------------------------------------------------------------------------------
const uint8_t MPUR_MEM_START_ADDR = (0x6E);
const uint8_t MPUR_MEM_R_W        = (0x6F);
const uint8_t MPUR_PRGM_START_H   = (0x70);
const uint8_t MPUR_PRGM_START_L   = (0x71);
const uint8_t MPUR_FIFO_COUNT_H   = (0x72);  // [15:0]
const uint8_t MPUR_FIFO_COUNT_L   = (0x73);
const uint8_t MPUR_FIFO_R_W       = (0x74);
const uint8_t MPUR_WHO_AM_I       = (0x75);

/*******************************************************************************
 * MPU6000, MPU6050 and MPU9150 registers
 ******************************************************************************/
const uint8_t MPUR_XG_OTP_OFFSET_TC = (0x00);  // [7] PWR_MODE, [6:1] XG_OFFS_TC, [0] OTP_BNK_VLD
//------------------------------------------------------------------------------
const uint8_t MPUR_YG_OTP_OFFSET_TC = (0x01);  // [7] PWR_MODE, [6:1] YG_OFFS_TC, [0] OTP_BNK_VLD
const uint8_t MPUR_TC_PWR_MODE_BIT  = (7);     // note: TC = temperature compensation, i think
//------------------------------------------------------------------------------
const uint8_t MPUR_ZG_OTP_OFFSET_TC = (0x02);  // [7] PWR_MODE, [6:1] ZG_OFFS_TC, [0] OTP_BNK_VLD
const uint8_t MPUR_X_FINE_GAIN      = (0x03);  // [7:0] X_FINE_GAIN
const uint8_t MPUR_Y_FINE_GAIN      = (0x04);  // [7:0] Y_FINE_GAIN
const uint8_t MPUR_Z_FINE_GAIN      = (0x05);  // [7:0] Z_FINE_GAIN
const uint8_t MPUR_XA_OFFSET_H      = (0x06);  // [15:1] XA_OFFS
const uint8_t MPUR_XA_OFFSET_L      = (0x07);  // note: TC: bit [0]
const uint8_t MPUR_YA_OFFSET_H      = (0x08);  // [15:1] YA_OFFS
const uint8_t MPUR_YA_OFFSET_L      = (0x09);  // note: TC: bit [0]
const uint8_t MPUR_ZA_OFFSET_H      = (0x0A);  // [15:1] ZA_OFFS
const uint8_t MPUR_ZA_OFFSET_L      = (0x0B);  // note: TC: bit [0]
const uint8_t MPUR_SELF_TEST_X      = (0x0D);
const uint8_t MPUR_SELF_TEST_Y      = (0x0E);
const uint8_t MPUR_SELF_TEST_Z      = (0x0F);
const uint8_t MPUR_SELF_TEST_A      = (0x10);
//------------------------------------------------------------------------------
const uint8_t MPUR_MOTION_DETECT_STATUS = (0x61);
const uint8_t MPUR_MOT_STATUS_X_NEG_BIT = (7);
const uint8_t MPUR_MOT_STATUS_X_POS_BIT = (6);
const uint8_t MPUR_MOT_STATUS_Y_NEG_BIT = (5);
const uint8_t MPUR_MOT_STATUS_Y_POS_BIT = (4);
const uint8_t MPUR_MOT_STATUS_Z_NEG_BIT = (3);
const uint8_t MPUR_MOT_STATUS_Z_POS_BIT = (2);
const uint8_t MPUR_MOT_STATUS_ZRMOT_BIT = (0);
//------------------------------------------------------------------------------
const uint8_t MPUR_MOTION_DETECT_CTRL            = (0x69);
const uint8_t MPUR_MOTCTRL_ACCEL_ON_DELAY_BIT    = (5);  // [5:4]
const uint8_t MPUR_MOTCTRL_ACCEL_ON_DELAY_LENGTH = (2);
const uint8_t MPUR_MOTCTRL_FF_COUNT_BIT          = (3);  // [3:2]
const uint8_t MPUR_MOTCTRL_FF_COUNT_LENGTH       = (2);
const uint8_t MPUR_MOTCTRL_MOT_COUNT_BIT         = (1);  // [1:0]
const uint8_t MPUR_MOTCTRL_MOT_COUNT_LENGTH      = (2);
//------------------------------------------------------------------------------

/*******************************************************************************
 * MPU6500 and MPU9250 registers
 ******************************************************************************/
#if defined CONFIG_MPU6500
const uint8_t MPUR_SELF_TEST_X_GYRO  = (0x00);  // XG_ST_DATA[7:0]
const uint8_t MPUR_SELF_TEST_Y_GYRO  = (0x01);  // YG_ST_DATA[7:0]
const uint8_t MPUR_SELF_TEST_Z_GYRO  = (0x02);  // ZG_ST_DATA[7:0]
const uint8_t MPUR_SELF_TEST_X_ACCEL = (0x0D);
const uint8_t MPUR_SELF_TEST_Y_ACCEL = (0x0E);
const uint8_t MPUR_SELF_TEST_Z_ACCEL = (0x0F);
//------------------------------------------------------------------------------
const uint8_t MPUR_ACCEL_CONFIG2                = (0x1D);
const uint8_t MPUR_ACONFIG2_FIFO_SIZE_BIT       = (7);  // [7:6]
const uint8_t MPUR_ACONFIG2_FIFO_SIZE_LENGTH    = (2);
const uint8_t MPUR_ACONFIG2_ACCEL_FCHOICE_B_BIT = (3);
const uint8_t MPUR_ACONFIG2_A_DLPF_CFG_BIT      = (2);  // [2:0]
const uint8_t MPUR_ACONFIG2_A_DLPF_CFG_LENGTH   = (3);
//------------------------------------------------------------------------------
const uint8_t MPUR_LP_ACCEL_ODR          = (0x1E);
const uint8_t MPUR_LPA_ODR_CLKSEL_BIT    = (3);  // [3:0]
const uint8_t MPUR_LPA_ODR_CLKSEL_LENGTH = (4);
//------------------------------------------------------------------------------
const uint8_t MPUR_ACCEL_INTEL_CTRL     = (0x69);
const uint8_t MPUR_ACCEL_INTEL_EN_BIT   = (7);
const uint8_t MPUR_ACCEL_INTEL_MODE_BIT = (6);
//------------------------------------------------------------------------------
const uint8_t MPUR_XA_OFFSET_H = (0x77);
const uint8_t MPUR_XA_OFFSET_L = (0x78);
const uint8_t MPUR_YA_OFFSET_H = (0x7A);
const uint8_t MPUR_YA_OFFSET_L = (0x7B);
const uint8_t MPUR_ZA_OFFSET_H = (0x7D);
const uint8_t MPUR_ZA_OFFSET_L = (0x7E);
#endif

/*******************************************************************************
 * MPU9150 and MPU9250 Magnetometer registers (AK89xx)
 ******************************************************************************/
#if defined CONFIG_MPU_AK89xx
const uint8_t MPUR_WHO_I_AM = (0x00);
const uint8_t MPUR_INFO     = (0x01);
//------------------------------------------------------------------------------
const uint8_t MPUR_STATUS1              = (0x02);
const uint8_t MPUR_STATUS1_DATA_RDY_BIT = (0);
//------------------------------------------------------------------------------
const uint8_t MPUR_HXL = (0x03);
const uint8_t MPUR_HXH = (0x04);
const uint8_t MPUR_HYL = (0x05);
const uint8_t MPUR_HYH = (0x06);
const uint8_t MPUR_HZL = (0x07);
const uint8_t MPUR_HZH = (0x08);
//------------------------------------------------------------------------------
const uint8_t MPUR_STATUS2              = (0x09);
const uint8_t MPUR_STATUS2_OVERFLOW_BIT = (3);
//------------------------------------------------------------------------------
const uint8_t MPUR_CONTROL1             = (0x0A);
const uint8_t MPUR_CONTROL1_MODE_BIT    = (3);
const uint8_t MPUR_CONTROL1_MODE_LENGTH = (4);
//------------------------------------------------------------------------------
const uint8_t MPUR_ASTC               = (0x0C);
const uint8_t MPUR_ASTC_SELF_TEST_BIT = (6);
//------------------------------------------------------------------------------
const uint8_t MPUR_TEST1 = (0x0D);
const uint8_t MPUR_TEST2 = (0x0E);
//------------------------------------------------------------------------------
const uint8_t MPUR_I2CDIS               = (0x0F);
const uint8_t MPUR_I2CDIS_DISABLE_VALUE = (0x1B);
//------------------------------------------------------------------------------
const uint8_t MPUR_ASAX = (0x10);
const uint8_t MPUR_ASAY = (0x11);
const uint8_t MPUR_ASAZ = (0x12);

/*******************************************************************************
 * MPU9150 Magnetometer (AK8975)
 ******************************************************************************/
#if defined CONFIG_MPU_AK8975
const uint8_t MPUR_STATUS2_DATA_ERROR_BIT = (2);
#endif

/*******************************************************************************
 * MPU9250 Magnetometer (AK8963)
 ******************************************************************************/
#if defined CONFIG_MPU_AK8963
const uint8_t MPUR_STATUS1_DATA_OVERRUN_BIT = (1);
const uint8_t MPUR_STATUS2_BIT_OUTPUT_M_BIT = (4);
const uint8_t MPUR_CONTROL1_BIT_OUTPUT_BIT  = (4);
//------------------------------------------------------------------------------
const uint8_t MPUR_CONTROL2                = (0x0B);
const uint8_t MPUR_CONTROL2_SOFT_RESET_BIT = (0);
//------------------------------------------------------------------------------
#endif

#endif

#endif /* end of include guard: _MPU_REGISTERS_HPP_ */
