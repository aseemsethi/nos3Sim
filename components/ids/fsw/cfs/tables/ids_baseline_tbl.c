/*******************************************************************************
** File: ids_baseline_tbl.c
**
** Purpose:
**   Default (empty) IDS baseline table. IDS_AppInit() loads this at startup
**   so there is always a valid table to CFE_TBL_GetAddress(), but the app's
**   actual working baseline (IDS_AppData.WorkingBaseline) starts from
**   IDS_Baseline_Init() the same way - this file only matters the first time
**   the app runs, or after IDS_LOAD_BASELINE_CC following a prior
**   IDS_CLEAR_BASELINE_CC + reset.
**
*******************************************************************************/
#include "cfe.h"
#include "cfe_tbl_filedef.h"
#include "ids_baseline.h"

/*
** Output filename must match IDS_BASELINE_FILENAME in ids_platform_cfg.h
** (basename <= 19 chars - see the comment there for why).
*/
static CFE_TBL_FileDef_t CFE_TBL_FileDef =
{
    "BaselineTbl", "IDS.BaselineTbl", "IDS learned-baseline table",
    "ids_base.tbl", sizeof(IDS_BaselineTbl_t)
};

/*
** All-zero is a valid, well-defined state: every Recorded flag false means
** "nothing learned yet", which is exactly what IDS_Baseline_Init() produces
** in memory.
*/
IDS_BaselineTbl_t ids_BaselineTable;
