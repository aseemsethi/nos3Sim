/*******************************************************************************
** File: ids_detector.c
**
** Purpose:
**  MONITOR-mode detection logic - see ids_detector.h.
**
*******************************************************************************/
#include <string.h>
#include <stdio.h>
#include "ids_detector.h"

void IDS_Detector_CheckEvent(IDS_BaselineTbl_t *Baseline, const char *AppName, uint16 EventId, uint64 NowMs,
                             double RateRatioThreshold, IDS_DetectorResult_t *Result)
{
    IDS_AppProfile_t *Profile = IDS_Baseline_FindApp(Baseline, AppName);
    int               i;
    bool              KnownEvent = false;
    double            IntervalMs;

    memset(Result, 0, sizeof(IDS_DetectorResult_t));

    if (Profile == NULL)
    {
        Result->IsAnomaly   = true;
        Result->AnomalyType = IDS_ANOMALY_UNKNOWN_APP;
        Result->Score       = 1.0;
        snprintf(Result->Description, sizeof(Result->Description), "no learned profile for app %s", AppName);
        return;
    }

    if (!Profile->Enabled)
    {
        /* Operator explicitly excluded this app from detection (IDS_DISABLE_APP_CC) */
        return;
    }

    for (i = 0; i < Profile->KnownEventCount; i++)
    {
        if (Profile->KnownEventIds[i] == EventId)
        {
            KnownEvent = true;
            break;
        }
    }

    if (!KnownEvent)
    {
        Result->IsAnomaly   = true;
        Result->AnomalyType = IDS_ANOMALY_UNKNOWN_EVENT;
        Result->Score       = 0.8;
        snprintf(Result->Description, sizeof(Result->Description), "app %s: event %u never seen while learning",
                 AppName, EventId);
        return;
    }

    /* NowMs >= LastEventTimeMs guard: the clock is NOS simulated time and can
    ** step backward across a sim restart; a uint64 underflow here would yield
    ** a near-2^64 interval and a bogus huge-score rate-flood false positive. */
    if (Profile->LastEventTimeMs != 0 && Profile->IntervalEwmaMs > 0.0 && NowMs >= Profile->LastEventTimeMs)
    {
        IntervalMs = (double)(NowMs - Profile->LastEventTimeMs);

        /* Guard divide-by-zero: two events in the same millisecond is itself
        ** the flood condition, treat it as ratio = infinity by comparing
        ** directly against the threshold-scaled learned interval instead of
        ** dividing. */
        if (IntervalMs * RateRatioThreshold < Profile->IntervalEwmaMs)
        {
            Result->IsAnomaly   = true;
            Result->AnomalyType = IDS_ANOMALY_RATE_FLOOD;
            Result->Score       = (float)(Profile->IntervalEwmaMs / (IntervalMs > 0.0 ? IntervalMs : 1.0));
            snprintf(Result->Description, sizeof(Result->Description),
                     "app %s: event %u arriving much faster than learned average", AppName, EventId);
            return;
        }
    }
}

bool IDS_Detector_IsSilent(const IDS_AppProfile_t *Profile, uint64 NowMs, uint32 SilenceTimeoutMs)
{
    if (!Profile->Recorded || !Profile->Enabled || Profile->LastEventTimeMs == 0)
    {
        return false;
    }
    return ((NowMs - Profile->LastEventTimeMs) > SilenceTimeoutMs);
}

bool IDS_Detector_CheckCiHk(uint16 NewCmdErrCount, uint16 LastCmdErrCount, uint16 SpikeThreshold)
{
    /* uint16 counters wrap; only compare when the new value is the larger one.
    ** A wrap (new < last) just resets the window rather than reporting a
    ** false spike. */
    if (NewCmdErrCount > LastCmdErrCount)
    {
        return ((uint16)(NewCmdErrCount - LastCmdErrCount) >= SpikeThreshold);
    }
    return false;
}

bool IDS_Detector_CheckCmdRate(uint32 NewTotalCmdCount, uint32 LastTotalCmdCount, uint64 NowMs, uint64 LastTimeMs,
                               double MaxCmdsPerSec, float *RateOut)
{
    double IntervalMs;
    double Rate;

    *RateOut = 0.0f;

    /* A counter reset (NewTotal < LastTotal - e.g. IDS_RESET_COUNTERS_CC or a
    ** ci/ci_lab restart) or a non-positive interval just re-baselines rather
    ** than computing a garbage/negative rate. */
    if (NewTotalCmdCount < LastTotalCmdCount || NowMs <= LastTimeMs)
    {
        return false;
    }

    IntervalMs = (double)(NowMs - LastTimeMs);
    Rate       = ((double)(NewTotalCmdCount - LastTotalCmdCount) * 1000.0) / IntervalMs;
    *RateOut   = (float)Rate;

    return (Rate > MaxCmdsPerSec);
}
