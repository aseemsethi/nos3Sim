/*******************************************************************************
** File: ids_detector.h
**
** Purpose:
**  MONITOR-mode logic: compares live activity against a learned IDS_BaselineTbl_t
**  and decides whether something looks anomalous. Pure functions - no bus or
**  EVS calls in here, ids_app.c owns publishing the result.
**
*******************************************************************************/
#ifndef _IDS_DETECTOR_H_
#define _IDS_DETECTOR_H_

#include "cfe.h"
#include "ids_baseline.h"
#include "ids_msg.h"

typedef struct
{
    bool   IsAnomaly;
    uint8  AnomalyType;
    float  Score;
    char   Description[64];

} IDS_DetectorResult_t;

/*
** Compare one observed (AppName, EventId) pair against the baseline.
** Fills Result->IsAnomaly = false if nothing looks wrong.
*/
void IDS_Detector_CheckEvent(IDS_BaselineTbl_t *Baseline, const char *AppName, uint16 EventId, uint64 NowMs,
                             double RateRatioThreshold, IDS_DetectorResult_t *Result);

/*
** True if a known, enabled app has not been heard from in SilenceTimeoutMs.
** Caller (ids_app.c) walks the AppProfile array and calls this once per app.
*/
bool IDS_Detector_IsSilent(const IDS_AppProfile_t *Profile, uint64 NowMs, uint32 SilenceTimeoutMs);

/*
** True if CI's rejected-command counter jumped by at least SpikeThreshold
** counts since the last HK packet we saw. This is the one detector that
** looks at the real external attack surface (the uplink) rather than
** internal bus behavior.
*/
bool IDS_Detector_CheckCiHk(uint8 NewCmdErrCount, uint8 LastCmdErrCount, uint8 SpikeThreshold);

#endif /* _IDS_DETECTOR_H_ */
