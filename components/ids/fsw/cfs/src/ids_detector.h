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
**
** Widths match CI_HkTlm_t.usCmdErrCnt (uint16) exactly - these used to be
** uint8 here, which silently truncated the real 16-bit counter and could
** mask a genuine spike that straddled a 256-count boundary.
*/
bool IDS_Detector_CheckCiHk(uint16 NewCmdErrCount, uint16 LastCmdErrCount, uint16 SpikeThreshold);

/*
** True if the combined valid+invalid command count (CmdCnt+CmdErrCnt) grew
** faster than MaxCmdsPerSec since the last HK sample - a volumetric uplink
** flood/DDoS indicator, independent of whether the commands were well-formed.
** Used for both CI and CI_LAB (see ids_app.c IDS_ProcessMirroredMessage).
** *RateOut always receives the computed rate (0.0 if not evaluated) so the
** caller can report it in the anomaly score/description either way.
*/
bool IDS_Detector_CheckCmdRate(uint32 NewTotalCmdCount, uint32 LastTotalCmdCount, uint64 NowMs, uint64 LastTimeMs,
                               double MaxCmdsPerSec, float *RateOut);

#endif /* _IDS_DETECTOR_H_ */
