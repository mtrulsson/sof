/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright(c) 2017 Intel Corporation. All rights reserved.
 *
 * Author: Liam Girdwood <liam.r.girdwood@linux.intel.com>
 *         Keyon Jie <yang.jie@linux.intel.com>
 *         Rander Wang <rander.wang@intel.com>
 */

#ifdef __SOF_LIB_SHIM_H__

#ifndef __PLATFORM_LIB_SHIM_H__
#define __PLATFORM_LIB_SHIM_H__

#include <ace/drivers/sideband-ipc.h>
#include <ace/lib/shim.h>

#include <sof/bit.h>
#include <sof/lib/memory.h>

/* DSP IPC for Host Registers */
#define IPC_DIPCTDR		0x00
#define IPC_DIPCTDA		0x04
#define IPC_DIPCTDD		0x08
#define IPC_DIPCIDR		0x10
#define IPC_DIPCIDA		0x14
#define IPC_DIPCIDD		0x180
#define IPC_DIPCCTL		0x28

#define DfIPCxTDR_REG       0x00
#define DfIPCxIDR_REG       0x10
#define DfIPCxIDA_REG       0x14
#define DfIPCxCTL_REG       0x28
#define DfIPCxTDDy_REG      0x100
#define DfIPCxIDDy_REG      0x180


#define IPC_DSP_OFFSET		0x10

/* DSP IPC for intra DSP communication */
#define IPC_IDCTFC(x)		(0x0 + x * IPC_DSP_OFFSET)
#define IPC_IDCTEFC(x)		(0x4 + x * IPC_DSP_OFFSET)
#define IPC_IDCITC(x)		(0x8 + x * IPC_DSP_OFFSET)
#define IPC_IDCIETC(x)		(0xc + x * IPC_DSP_OFFSET)
#define IPC_IDCCTL		0x50

/* IDCTFC */
#define IPC_IDCTFC_BUSY		BIT(31)
#define IPC_IDCTFC_MSG_MASK	0x7FFFFFFF

/* IDCTEFC */
#define IPC_IDCTEFC_MSG_MASK	0x3FFFFFFF

/* IDCITC */
#define IPC_IDCITC_BUSY		BIT(31)
#define IPC_IDCITC_MSG_MASK	0x7FFFFFFF

/* IDCIETC */
#define IPC_IDCIETC_DONE	BIT(30)
#define IPC_IDCIETC_MSG_MASK	0x3FFFFFFF

/* IDCCTL */
#define IPC_IDCCTL_IDCIDIE(x)	(0x100 << (x))
#define IPC_IDCCTL_IDCTBIE(x)	BIT(x)

#define IRQ_CPU_OFFSET	0x40

#define REG_IRQ_IL2MSD(xcpu)	(0x0 + (xcpu * IRQ_CPU_OFFSET))
#define REG_IRQ_IL2MCD(xcpu)	(0x4 + (xcpu * IRQ_CPU_OFFSET))
#define REG_IRQ_IL2MD(xcpu)	(0x8 + (xcpu * IRQ_CPU_OFFSET))
#define REG_IRQ_IL2SD(xcpu)	(0xc + (xcpu * IRQ_CPU_OFFSET))

/* all mask valid bits */
#define REG_IRQ_IL2MD_ALL		0x03F181F0

#define REG_IRQ_IL3MSD(xcpu)	(0x10 + (xcpu * IRQ_CPU_OFFSET))
#define REG_IRQ_IL3MCD(xcpu)	(0x14 + (xcpu * IRQ_CPU_OFFSET))
#define REG_IRQ_IL3MD(xcpu)	(0x18 + (xcpu * IRQ_CPU_OFFSET))
#define REG_IRQ_IL3SD(xcpu)	(0x1c + (xcpu * IRQ_CPU_OFFSET))

/* all mask valid bits */
#define REG_IRQ_IL3MD_ALL		0x807F81FF

#define REG_IRQ_IL4MSD(xcpu)	(0x20 + (xcpu * IRQ_CPU_OFFSET))
#define REG_IRQ_IL4MCD(xcpu)	(0x24 + (xcpu * IRQ_CPU_OFFSET))
#define REG_IRQ_IL4MD(xcpu)	(0x28 + (xcpu * IRQ_CPU_OFFSET))
#define REG_IRQ_IL4SD(xcpu)	(0x2c + (xcpu * IRQ_CPU_OFFSET))

/* all mask valid bits */
#define REG_IRQ_IL4MD_ALL		0x807F81FF

#define REG_IRQ_IL5MSD(xcpu)	(0x30 + (xcpu * IRQ_CPU_OFFSET))
#define REG_IRQ_IL5MCD(xcpu)	(0x34 + (xcpu * IRQ_CPU_OFFSET))
#define REG_IRQ_IL5MD(xcpu)	(0x38 + (xcpu * IRQ_CPU_OFFSET))
#define REG_IRQ_IL5SD(xcpu)	(0x3c + (xcpu * IRQ_CPU_OFFSET))

/* all mask valid bits */
#define REG_IRQ_IL5MD_ALL		0xFFFFC0CF

#define REG_IRQ_IL2RSD		0x100
#define REG_IRQ_IL3RSD		0x104
#define REG_IRQ_IL4RSD		0x108
#define REG_IRQ_IL5RSD		0x10c

#define REG_IRQ_LVL5_LP_GPDMA0_MASK		(0xff << 16)
#define REG_IRQ_LVL5_LP_GPDMA1_MASK		(0xff << 24)

/* DSP Shim Registers */
#define DfTTS_SHIM_BASE	0x72000
#define SHIM_DSPWCTS		(DfTTS_SHIM_BASE + 0x12) /* DSP Wall Clock status */
#define SHIM_DSPWC			(DfTTS_SHIM_BASE + 0x20) /* DSP Wall Clock */
#define SHIM_DSPWCL			(DfTTS_SHIM_BASE + 0x20) /* DSP Wall Clock Low */
#define SHIM_DSPWCH			(DfTTS_SHIM_BASE + 0x24) /* DSP Wall Clock High */
#define SHIM_DSPWCTCS		(DfTTS_SHIM_BASE + 0x28) /* DSP Wall Clock Timer Control & Status */
#define SHIM_DSPWCT0C		(DfTTS_SHIM_BASE + 0x30) /* DSP Wall Clock Timer 0 Compare */
#define SHIM_DSPWCT1C		(DfTTS_SHIM_BASE + 0x38) /* DSP Wall Clock Timer 1 Compare */

#define SHIM_DSPWCTCS_T1TIE     BIT(9) /* Timer 1 Triggered Interrupt Enable */
#define SHIM_DSPWCTCS_T0TIE     BIT(8) /* Timer 0 Triggered Interrupt Enable */
#define SHIM_DSPWCTCS_T1T	BIT(5) /* Timer 1 triggered */
#define SHIM_DSPWCTCS_T0T	BIT(4) /* Timer 0 triggered */
#define SHIM_DSPWCTCS_T1A	BIT(1) /* Timer 1 armed */
#define SHIM_DSPWCTCS_T0A	BIT(0) /* Timer 0 armed */

/** \brief Clock control */
#define SHIM_CLKCTL		0x78

/** \brief Request HP RING Oscillator Clock */
#define SHIM_CLKCTL_RHROSCC	BIT(31)

/** \brief Request WOVCRO Clock */
#define SHIM_CLKCTL_WOV_CRO_REQUEST	BIT(4)

/** \brief Request XTAL Oscillator Clock */
#define SHIM_CLKCTL_RXOSCC	BIT(30)

/** \brief Request LP RING Oscillator Clock */
#define SHIM_CLKCTL_RLROSCC	BIT(29)

/** \brief Tensilica Core Prevent Local Clock Gating */
#define SHIM_CLKCTL_TCPLCG_EN(x)	BIT(16 + (x))
#define SHIM_CLKCTL_TCPLCG_DIS(x)	0
#define SHIM_CLKCTL_TCPLCG_DIS_ALL	(SHIM_CLKCTL_TCPLCG_DIS(0) | \
					 SHIM_CLKCTL_TCPLCG_DIS(1) | \
					 SHIM_CLKCTL_TCPLCG_DIS(2) | \
					 SHIM_CLKCTL_TCPLCG_DIS(3))

/** \brief Oscillator Clock Select*/
#define SHIM_CLKCTL_OCS_HP_RING		BIT(2)
#define SHIM_CLKCTL_OCS_LP_RING		0
#define SHIM_CLKCTL_WOVCROSC		BIT(3)

/** \brief LP Memory Clock Select */
#define SHIM_CLKCTL_LMCS_DIV2	0
#define SHIM_CLKCTL_LMCS_DIV4	BIT(1)

/** \brief HP Memory Clock Select */
#define SHIM_CLKCTL_HMCS_DIV2	0
#define SHIM_CLKCTL_HMCS_DIV4	BIT(0)

/* Core clock PLL divisor */
#define SHIM_CLKCTL_DPCS_MASK(x)	BIT(2)

/* Prevent Audio PLL Shutdown */
#define SHIM_CLKCTL_TCPAPLLS	BIT(7)

/* 0--from PLL, 1--from oscillator */
#define SHIM_CLKCTL_HDCS	BIT(4)

/* Oscillator select */
#define SHIM_CLKCTL_HDOCS	BIT(2)

/* HP memory clock PLL divisor */
#define SHIM_CLKCTL_HPMPCS	BIT(0)

/** \brief Mask for requesting clock
 */
#define SHIM_CLKCTL_OSC_REQUEST_MASK \
	(SHIM_CLKCTL_RHROSCC | SHIM_CLKCTL_RXOSCC | \
	SHIM_CLKCTL_RLROSCC)

/** \brief Mask for setting previously requested clock
 */
#define SHIM_CLKCTL_OSC_SOURCE_MASK \
	(SHIM_CLKCTL_OCS_HP_RING | SHIM_CLKCTL_LMCS_DIV4 | \
	SHIM_CLKCTL_HMCS_DIV4)

/** \brief Clock status */
#define SHIM_CLKSTS		0x7C

/** \brief HP RING Oscillator Clock Status */
#define SHIM_CLKSTS_HROSCCS	BIT(31)

/** \brief WOVCRO Clock Status */
#define SHIM_CLKSTS_WOV_CRO	BIT(4)

/** \brief XTAL Oscillator Clock Status */
#define SHIM_CLKSTS_XOSCCS	BIT(30)

/** \brief LP RING Oscillator Clock Status */
#define SHIM_CLKSTS_LROSCCS	BIT(29)

#define SHIM_PM_BASE		0x71B00

#define SHIM_PWRCTL		(SHIM_PM_BASE + 0x90)
#define SHIM_PWRCTL_TCPDSPPG(x)	BIT(x)
#define SHIM_PWRCTL_TCPCTLPG	BIT(4)

#define SHIM_PWRSTS		(SHIM_PM_BASE + 0x92)

#define SHIM_LPSCTL		(SHIM_PM_BASE + 0x94)
#define SHIM_LPSCTL_BID		BIT(7)
#define SHIM_LPSCTL_FDSPRUN	BIT(9)
#define SHIM_LPSCTL_BATTR_0	BIT(12)

/** \brief GPDMA shim registers Control */
#define SHIM_GPDMA_BASE(x)	(0x7C800 + (x) * 0x1000)

/** \brief GPDMA Clock Control */
#define SHIM_GPDMA_CLKCTL(x)	(SHIM_GPDMA_BASE(x) + 0x4)

/* LP GPDMA Set Power Active bit, 1--enable */
#define SHIM_CLKCTL_LPGPDMA_SPA	BIT(0)
/* LP GPDMA Current Power Active bit, 1--enable */
#define SHIM_CLKCTL_LPGPDMA_CPA	BIT(8)
/* LP GPDMA Dynamic Clock Gating Disable bit, 0--enable */
#define SHIM_CLKCTL_LPGPDMA_DGCD BIT(30)
/* LP GPDMA Owner Select */
#define SHIM_CLKCTL_LPGPDMA_OSEL(x)		SET_BITS(25, 24, x)

/** \brief GPDMA Channel Linear Link Position Control */
#define SHIM_GPDMA_CHLLPC(x, y)		(SHIM_GPDMA_BASE(x) + 0x10 + (y) * 0x10)
#define SHIM_GPDMA_CHLLPC_EN		BIT(7)
#define SHIM_GPDMA_CHLLPC_DHRS(x)	SET_BITS(6, 0, x)

#define SHIM_GPDMA_CHLLPL(x, y)                (SHIM_GPDMA_BASE(x) + 0x18 + (y) * 0x10)
#define SHIM_GPDMA_CHLLPU(x, y)                (SHIM_GPDMA_BASE(x) + 0x1c + (y) * 0x10)

/* I2S SHIM Registers */
#define I2SLCTL			0x28804

/* SPA register should be set for each I2S port and DSP should
 * wait for CPA to be set
 */
#define I2SLCTL_SPA(x)		BIT(0 + x)
#define I2SLCTL_CPA(x)		BIT(8 + x)

#define L2LMCAP			0x71D00
#define L2MPAT			0x71D04

#define L2HSBPM(x)		(0x17A800 + 0x0008 * (x))
#define SHIM_HSPGCTL(x)		(L2HSBPM(x) + 0x0000)
#define SHIM_HSRMCTL(x)		(L2HSBPM(x) + 0x0001)
#define SHIM_HSPGISTS(x)	(L2HSBPM(x) + 0x0004)

#define LSPGCTL			0x71D80
#define LSRMCTL			0x71D81
#define LSPGISTS		0x71D84

#define SHIM_L2_MECS		(SHIM_BASE + 0xd0)

/** \brief LDO Control */
#define SHIM_LDOCTL		0xA4
#define SHIM_LDOCTL_HPSRAM_MASK	(3 << 0 | 3 << 16)
#define SHIM_LDOCTL_LPSRAM_MASK	(3 << 2)
#define SHIM_LDOCTL_HPSRAM_LDO_ON	(3 << 0 | 3 << 10)

#define HPSRAM_LDO_1_ON	(3 << 0)
#define HPSRAM_LDO_2_ON	(3 << 10)
#define HPSRAM_LDO_ON	(HPSRAM_LDO_1_ON | HPSRAM_LDO_2_ON)

#define SHIM_LDOCTL_LPSRAM_LDO_ON	(3 << 2)
#define SHIM_LDOCTL_HPSRAM_LDO_BYPASS	(BIT(0) | BIT(16))
#define SHIM_LDOCTL_LPSRAM_LDO_BYPASS	BIT(2)
#define SHIM_LDOCTL_HPSRAM_LDO_OFF	(0 << 0)
#define SHIM_LDOCTL_LPSRAM_LDO_OFF	(0 << 2)

#define DSP_INIT_LPGPDMA(x)	(0x71A60 + (2*x))
#define LPGPDMA_CTLOSEL_FLAG	BIT(15)
#define LPGPDMA_CHOSEL_FLAG	0xFF

#define DSP_INIT_IOPO	0x71A68
#define IOPO_DMIC_FLAG		BIT(0)
#define IOPO_I2S_FLAG		MASK(DAI_NUM_SSP_BASE + DAI_NUM_SSP_EXT + 7, 8)

#define DSP_INIT_GENO	0x71A6C
#define GENO_MDIVOSEL		BIT(1)
#define GENO_DIOPTOSEL		BIT(2)

#define ALHASCTL_OSEL(x)		SET_BITS(25, 24, x)
#define ALHCSCTL_OSEL(x)		SET_BITS(25, 24, x)

#define PMC_BASE					0x71AC0
#define SHIM_SVCFG					(PMC_BASE + 0x18)
#define SHIM_SVCFG_FORCE_L1_EXIT	BIT(1)

/* host windows */
#define DMWBA(x)		(HOST_WIN_BASE(x) + 0x0)
#define DMWLO(x)		(HOST_WIN_BASE(x) + 0x4)

#define DMWBA_ENABLE		BIT(0)
#define DMWBA_READONLY		BIT(1)

/* DMIC power ON bit */
#define DMICLCTL_SPA		BIT(0)
/* DMIC Owner Select */
#define DMICLCTL_OSEL(x)	SET_BITS(25, 24, x)
/* DMIC disable clock gating */
#define DMIC_DCGD			BIT(30)

/* DMIC Command Sync */
#define DMICSYNC_CMDSYNC	BIT(16)
/* DMIC Sync Go */
#define DMICSYNC_SYNCGO		BIT(24)
/* DMIC Sync Period */
#define DMICSYNC_SYNCPRD(x)	SET_BITS(14, 0, x)

#endif /* __PLATFORM_LIB_SHIM_H__ */

#else

#error "This file shouldn't be included from outside of sof/lib/shim.h"

#endif /* __SOF_LIB_SHIM_H__ */
