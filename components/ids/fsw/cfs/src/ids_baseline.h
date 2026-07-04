/*******************************************************************************
** File: ids_baseline.h
**
** Purpose:
**  Fixed-size, no-dynamic-allocation model of "normal" bus behavior, learned
**  from EVS events (per app) and raw bus traffic (per MID). This is the data
**  structure that IDS_SET_MODE_CC(LEARN) fills in and IDS_SET_MODE_CC(MONITOR)
**  compares live activity against.
**
*******************************************************************************/
#ifndef _IDS_BASELINE_H_
#define _IDS_BASELINE_H_

#include "cfe.h"
#include "ids_platform_cfg.h"

/*
** Learned profile of one MID observed on the mirrored bus.
** Used for MID-level rate/silence features that aren't tied to an EVS event.
*/
typedef struct
{
    bool           Recorded;
    CFE_SB_MsgId_t MsgId;
    uint32         MsgCount;
    uint64         LastSeenTimeMs;
    double         IntervalEwmaMs; /* smoothed average time between messages */

} IDS_MidProfile_t;

/*
** Learned profile of one app observed via EVS events.
*/
typedef struct
{
    bool   Recorded;
    bool   Enabled; /* false = operator excluded this app via IDS_DISABLE_APP_CC */
    char   AppName[CFE_MISSION_MAX_API_LEN];
    uint16 KnownEventIds[IDS_MAX_EVENTS_PER_APP];
    uint8  KnownEventCount;
    uint32 EventCount;
    uint64 LastEventTimeMs;
    double IntervalEwmaMs; /* smoothed average time between events, any event ID */

} IDS_AppProfile_t;

/*
** The full baseline. This is what gets registered as a CFE_TBL so it can be
** dumped to a file on the ground and reloaded across a reset via the normal
** table services ground commands (dump/load target the registered table name
** "IDS.BaselineTbl" - IDS itself does not do file I/O).
*/
typedef struct
{
    IDS_AppProfile_t AppProfile[IDS_MAX_TRACKED_APPS];
    IDS_MidProfile_t MidProfile[IDS_MAX_TRACKED_MIDS];

} IDS_BaselineTbl_t;

void IDS_Baseline_Init(IDS_BaselineTbl_t *Baseline);

IDS_AppProfile_t *IDS_Baseline_FindApp(IDS_BaselineTbl_t *Baseline, const char *AppName);
IDS_AppProfile_t *IDS_Baseline_FindOrAddApp(IDS_BaselineTbl_t *Baseline, const char *AppName, bool *IsNew);

IDS_MidProfile_t *IDS_Baseline_FindMid(IDS_BaselineTbl_t *Baseline, CFE_SB_MsgId_t MsgId);
IDS_MidProfile_t *IDS_Baseline_FindOrAddMid(IDS_BaselineTbl_t *Baseline, CFE_SB_MsgId_t MsgId, bool *IsNew);

/* Update (or create) an app's profile with one more observed event, LEARN mode only */
void IDS_Baseline_LearnEvent(IDS_BaselineTbl_t *Baseline, const char *AppName, uint16 EventId, uint64 NowMs);

/* Update (or create) a MID's profile with one more observed message, LEARN mode only */
void IDS_Baseline_LearnMid(IDS_BaselineTbl_t *Baseline, CFE_SB_MsgId_t MsgId, uint64 NowMs);

/* CFE_TBL_Register validation callback */
int32 IDS_ValidateBaselineTbl(void *TblData);

#endif /* _IDS_BASELINE_H_ */
