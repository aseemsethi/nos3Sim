/*******************************************************************************
** File: ids_baseline.c
**
** Purpose:
**  Learning-side logic for the IDS baseline: fixed-capacity lookup and
**  update of per-app (EVS) and per-MID (bus) profiles. No dynamic memory,
**  no unbounded loops - every table here is sized at compile time via
**  ids_platform_cfg.h so behavior is deterministic on a flight CPU.
**
*******************************************************************************/
#include <string.h>
#include "ids_baseline.h"

/* Smoothing factor for the interval EWMA. Weighted toward history on
** purpose - one single fast or slow message should not swing the baseline. */
#define IDS_EWMA_ALPHA 0.2

static void IDS_Baseline_UpdateInterval(double *Ewma, uint64 *LastTimeMs, uint64 NowMs)
{
    /* Guard against non-monotonic time: the clock here is NOS simulated time,
    ** which can step backward across a sim restart. A naive uint64 subtraction
    ** would then underflow to a near-2^64 "interval" and poison the EWMA. */
    if (*LastTimeMs != 0 && NowMs >= *LastTimeMs)
    {
        double IntervalMs = (double)(NowMs - *LastTimeMs);

        if (*Ewma <= 0.0)
        {
            *Ewma = IntervalMs;
        }
        else
        {
            *Ewma = (*Ewma * (1.0 - IDS_EWMA_ALPHA)) + (IntervalMs * IDS_EWMA_ALPHA);
        }
    }
    *LastTimeMs = NowMs;
}

void IDS_Baseline_Init(IDS_BaselineTbl_t *Baseline)
{
    memset(Baseline, 0, sizeof(IDS_BaselineTbl_t));
}

IDS_AppProfile_t *IDS_Baseline_FindApp(IDS_BaselineTbl_t *Baseline, const char *AppName)
{
    int i;

    for (i = 0; i < IDS_MAX_TRACKED_APPS; i++)
    {
        if (Baseline->AppProfile[i].Recorded && (strncmp(Baseline->AppProfile[i].AppName, AppName,
                                                          CFE_MISSION_MAX_API_LEN) == 0))
        {
            return &Baseline->AppProfile[i];
        }
    }
    return NULL;
}

IDS_AppProfile_t *IDS_Baseline_FindOrAddApp(IDS_BaselineTbl_t *Baseline, const char *AppName, bool *IsNew)
{
    IDS_AppProfile_t *Profile = IDS_Baseline_FindApp(Baseline, AppName);
    int               i;

    *IsNew = false;
    if (Profile != NULL)
    {
        return Profile;
    }

    for (i = 0; i < IDS_MAX_TRACKED_APPS; i++)
    {
        if (!Baseline->AppProfile[i].Recorded)
        {
            memset(&Baseline->AppProfile[i], 0, sizeof(IDS_AppProfile_t));
            strncpy(Baseline->AppProfile[i].AppName, AppName, CFE_MISSION_MAX_API_LEN - 1);
            Baseline->AppProfile[i].Recorded = true;
            Baseline->AppProfile[i].Enabled  = true;
            *IsNew                           = true;
            return &Baseline->AppProfile[i];
        }
    }

    /* Table is full - caller (ids_app.c) logs IDS_BASELINE_FULL_ERR_EID */
    return NULL;
}

IDS_MidProfile_t *IDS_Baseline_FindMid(IDS_BaselineTbl_t *Baseline, CFE_SB_MsgId_t MsgId)
{
    int i;

    for (i = 0; i < IDS_MAX_TRACKED_MIDS; i++)
    {
        if (Baseline->MidProfile[i].Recorded && CFE_SB_MsgId_Equal(Baseline->MidProfile[i].MsgId, MsgId))
        {
            return &Baseline->MidProfile[i];
        }
    }
    return NULL;
}

IDS_MidProfile_t *IDS_Baseline_FindOrAddMid(IDS_BaselineTbl_t *Baseline, CFE_SB_MsgId_t MsgId, bool *IsNew)
{
    IDS_MidProfile_t *Profile = IDS_Baseline_FindMid(Baseline, MsgId);
    int               i;

    *IsNew = false;
    if (Profile != NULL)
    {
        return Profile;
    }

    for (i = 0; i < IDS_MAX_TRACKED_MIDS; i++)
    {
        if (!Baseline->MidProfile[i].Recorded)
        {
            memset(&Baseline->MidProfile[i], 0, sizeof(IDS_MidProfile_t));
            Baseline->MidProfile[i].MsgId    = MsgId;
            Baseline->MidProfile[i].Recorded = true;
            *IsNew                           = true;
            return &Baseline->MidProfile[i];
        }
    }

    /* Table is full - caller (ids_app.c) logs IDS_BASELINE_FULL_ERR_EID */
    return NULL;
}

void IDS_Baseline_LearnEvent(IDS_BaselineTbl_t *Baseline, const char *AppName, uint16 EventId, uint64 NowMs)
{
    bool              IsNew;
    IDS_AppProfile_t *Profile = IDS_Baseline_FindOrAddApp(Baseline, AppName, &IsNew);
    int               i;
    bool              KnownEvent = false;

    if (Profile == NULL)
    {
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

    if (!KnownEvent && Profile->KnownEventCount < IDS_MAX_EVENTS_PER_APP)
    {
        Profile->KnownEventIds[Profile->KnownEventCount] = EventId;
        Profile->KnownEventCount++;
    }

    Profile->EventCount++;
    IDS_Baseline_UpdateInterval(&Profile->IntervalEwmaMs, &Profile->LastEventTimeMs, NowMs);
}

void IDS_Baseline_LearnMid(IDS_BaselineTbl_t *Baseline, CFE_SB_MsgId_t MsgId, uint64 NowMs)
{
    bool              IsNew;
    IDS_MidProfile_t *Profile = IDS_Baseline_FindOrAddMid(Baseline, MsgId, &IsNew);

    if (Profile == NULL)
    {
        return;
    }

    Profile->MsgCount++;
    IDS_Baseline_UpdateInterval(&Profile->IntervalEwmaMs, &Profile->LastSeenTimeMs, NowMs);
}

int32 IDS_ValidateBaselineTbl(void *TblData)
{
    /* The baseline is content-agnostic (any combination of Recorded flags is
    ** valid - an empty table is a legitimate "just cleared" state), so there
    ** is nothing to reject here. The callback still has to exist to satisfy
    ** CFE_TBL_Register. */
    (void)TblData;
    return CFE_SUCCESS;
}
