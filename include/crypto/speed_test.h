/*
 * @Author: RyanCLQ
 * @Date: 2023-06-13 11:07:58
 * @LastEditors: RyanCLQ
 * @LastEditTime: 2023-06-18 15:25:02
 * @Description: 请填写简介
 */
#ifndef WBCRYPTO_SPEED_TEST_H
#define WBCRYPTO_SPEED_TEST_H

#include <stdio.h>
#include <omp.h>

#include "wbcrypto/wbaes.h"
#include "wbcrypto/wbsm4_se.h"
#include "wbcrypto/wbsm4_xl.h"
#include "wbcrypto/wbsm4_xl_la.h"

#define WBAES_CEJO 0
#define WBSM4_SE 1
#define WBSM4_XL 2
#define WBSM4_XL_LA 3

#define ECB 0
#define CBC 1
#define CTR 2
#define GCM 3

#ifdef __cplusplus
extern "C" {
#endif

    int wbcrypto_block_cipher_speed_test(int algorithm, int mode, int threads_num);

#ifdef __cplusplus
}
#endif

#endif /* speed_test.h */
