/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright(c) 2022 Intel Corporation. All rights reserved.
 *
 */

#include <sof/audio/src/src.h>
#include <stdint.h>

const int32_t src_int32_21_20_1250_5000_fir[252] = {
	-628693,
	-3133095,
	36139645,
	-42910156,
	-164094935,
	605644236,
	1341104262,
	550861758,
	-172902533,
	-32718751,
	34197150,
	-3630581,
	-814598,
	-2494388,
	37831351,
	-53548329,
	-152759298,
	660617664,
	1336669937,
	496571898,
	-179293495,
	-23048651,
	32052265,
	-3996957,
	-1026262,
	-1705564,
	39222637,
	-64547375,
	-138799328,
	715471397,
	1327831537,
	443065078,
	-183392700,
	-13963005,
	29751634,
	-4243268,
	-1262559,
	-759232,
	40263228,
	-75810204,
	-122135391,
	769888216,
	1314649286,
	390618340,
	-185336797,
	-5513666,
	27339686,
	-4381232,
	-1521551,
	350214,
	40902843,
	-87228835,
	-102705945,
	823546833,
	1297212845,
	339493382,
	-185272447,
	2258595,
	24858231,
	-4422974,
	-1800424,
	1626302,
	41091880,
	-98684834,
	-80468853,
	876124470,
	1275640496,
	289934777,
	-183354537,
	9323765,
	22346130,
	-4380796,
	-2095436,
	3070211,
	40782152,
	-110049902,
	-55402537,
	927299495,
	1250078087,
	242168383,
	-179744389,
	15662165,
	19839025,
	-4266952,
	-2401882,
	4680503,
	39927657,
	-121186592,
	-27506984,
	976754086,
	1220697722,
	196399964,
	-174607971,
	21263935,
	17369132,
	-4093452,
	-2714064,
	6452872,
	38485376,
	-131949184,
	3195441,
	1024176897,
	1187696218,
	152814031,
	-168114141,
	26128441,
	14965106,
	-3871885,
	-3025293,
	8379928,
	36416089,
	-142184681,
	36659368,
	1069265696,
	1151293363,
	111572902,
	-160432940,
	30263609,
	12651949,
	-3613263,
	-3327898,
	10450994,
	33685209,
	-151733941,
	72815998,
	1111729956,
	1111729956,
	72815998,
	-151733941,
	33685209,
	10450994,
	-3327898,
	-3613263,
	12651949,
	30263609,
	-160432940,
	111572902,
	1151293363,
	1069265696,
	36659368,
	-142184681,
	36416089,
	8379928,
	-3025293,
	-3871885,
	14965106,
	26128441,
	-168114141,
	152814031,
	1187696218,
	1024176897,
	3195441,
	-131949184,
	38485376,
	6452872,
	-2714064,
	-4093452,
	17369132,
	21263935,
	-174607971,
	196399964,
	1220697722,
	976754086,
	-27506984,
	-121186592,
	39927657,
	4680503,
	-2401882,
	-4266952,
	19839025,
	15662165,
	-179744389,
	242168383,
	1250078087,
	927299495,
	-55402537,
	-110049902,
	40782152,
	3070211,
	-2095436,
	-4380796,
	22346130,
	9323765,
	-183354537,
	289934777,
	1275640496,
	876124470,
	-80468853,
	-98684834,
	41091880,
	1626302,
	-1800424,
	-4422974,
	24858231,
	2258595,
	-185272447,
	339493382,
	1297212845,
	823546833,
	-102705945,
	-87228835,
	40902843,
	350214,
	-1521551,
	-4381232,
	27339686,
	-5513666,
	-185336797,
	390618340,
	1314649286,
	769888216,
	-122135391,
	-75810204,
	40263228,
	-759232,
	-1262559,
	-4243268,
	29751634,
	-13963005,
	-183392700,
	443065078,
	1327831537,
	715471397,
	-138799328,
	-64547375,
	39222637,
	-1705564,
	-1026262,
	-3996957,
	32052265,
	-23048651,
	-179293495,
	496571898,
	1336669937,
	660617664,
	-152759298,
	-53548329,
	37831351,
	-2494388,
	-814598,
	-3630581,
	34197150,
	-32718751,
	-172902533,
	550861758,
	1341104262,
	605644236,
	-164094935,
	-42910156,
	36139645,
	-3133095,
	-628693

};

struct src_stage src_int32_21_20_1250_5000 = {
	19, 20, 21, 12, 252, 20, 21, 0, 0,
	src_int32_21_20_1250_5000_fir};