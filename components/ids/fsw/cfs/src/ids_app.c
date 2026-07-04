/*******************************************************************************
** File: ids_app.c
**
** Purpose:
**   This file contains the source code for the IDS application: a passive
**   bus-wide anomaly detector / intrusion detection system. By default it
**   observes every EVS event in the system, learns what "normal" looks like
**   per app, and raises an anomaly when live behavior deviates.
**
**   On command (IDS_SET_MIRROR_CC) it can additionally run a time-bounded
**   "deep bus mirror": it enables system-wide SB subscription reporting (the
**   CFE_SB_ONESUB_TLM_MID mechanism, the same one SBN uses to decide what to
**   forward) and mirror-subscribes to every MID on the bus, enabling
**   MID-level rate and CI-reject detectors. Because that generates a
**   subscription-report storm, the mirror runs on a DEDICATED pipe (so the
**   command/HK pipe stays responsive) and auto-disables after the commanded
**   window - off by default.
**
*******************************************************************************/

/*
** Include Files
*/
#include <string.h>
#include <stdio.h>
#include "ids_app.h"
#include "cfe_msgids.h"  /* CFE_SB_SUB_RPT_CTRL_MID, CFE_SB_ONESUB_TLM_MID, CFE_EVS_LONG_EVENT_MSG_MID */
#include "cfe_sb_msg.h"  /* CFE_SB_SingleSubscriptionTlm_t, CFE_SB_ENABLE_SUB_REPORTING_CC, CFE_SB_SEND_PREV_SUBS_CC */
#include "cfe_evs_msg.h" /* CFE_EVS_LongEventTlm_t */
#include "cfe_tbl_msg.h" /* CFE_TBL_DumpCmd_t, CFE_TBL_DUMP_CC, CFE_TBL_BufferSelect_ACTIVE */
#include "ci_msgids.h"   /* CI_HK_TLM_MID */
#include "ci_hktlm.h"    /* CI_HkTlm_t */

/*
** Global Data
*/
IDS_AppData_t IDS_AppData;

/*
** Application entry point and main process loop
*/
void IDS_AppMain(void)
{
    int32 status = OS_SUCCESS;

    CFE_ES_PerfLogEntry(IDS_PERF_ID);

    status = IDS_AppInit();
    if (status != CFE_SUCCESS)
    {
        IDS_AppData.RunStatus = CFE_ES_RunStatus_APP_ERROR;
    }

    while (CFE_ES_RunLoop(&IDS_AppData.RunStatus) == true)
    {
        CFE_ES_PerfLogExit(IDS_PERF_ID);

        /*
        ** Unlike a typical app, IDS uses a timeout instead of PEND_FOREVER.
        ** It must keep running (HK, silence detection) even during a lull
        ** in bus traffic, and it must not depend on SCH being wired up to
        ** request its HK - it drives its own cadence.
        */
        status = CFE_SB_ReceiveBuffer((CFE_SB_Buffer_t **)&IDS_AppData.MsgPtr, IDS_AppData.CmdPipe,
                                      IDS_SB_TIMEOUT_MS);

        CFE_ES_PerfLogEntry(IDS_PERF_ID);

        if (status == CFE_SUCCESS)
        {
            IDS_ProcessCommandPacket();

            /*
            ** Fallback HK trigger for busy stretches where the pipe never
            ** idles: publish after this many processed messages.
            */
            if (++IDS_AppData.MsgsSinceHk >= IDS_HK_MSG_INTERVAL)
            {
                IDS_CheckSilence();
                IDS_ReportHousekeeping();
                IDS_AppData.MsgsSinceHk = 0;
            }
        }
        else if (status == CFE_SB_TIME_OUT)
        {
            /*
            ** Primary HK trigger: the pipe went idle for IDS_SB_TIMEOUT_MS.
            ** With the bus mirror off (default), IDS sees only EVS events plus
            ** its own commands, so the pipe idles regularly and this fires at
            ** roughly the timeout rate. This is deliberately clock-independent:
            ** the only clock here is NOS *simulated* time (tone-driven,
            ** quantized, non-monotonic across sim restarts), so gating HK on an
            ** elapsed-sim-time delta is unreliable.
            */
            IDS_CheckSilence();
            IDS_ReportHousekeeping();
            IDS_AppData.MsgsSinceHk = 0;
        }
        else
        {
            CFE_EVS_SendEvent(IDS_PIPE_ERR_EID, CFE_EVS_EventType_ERROR, "IDS: SB Pipe Read Error = %d",
                              (int)status);
            IDS_AppData.RunStatus = CFE_ES_RunStatus_APP_ERROR;
        }

        /*
        ** When the deep mirror is on, service its dedicated pipe (bounded, so
        ** it can never starve the command/HK path above) and auto-disable it
        ** once the commanded window has elapsed.
        */
        if (IDS_AppData.MirrorActive)
        {
            IDS_DrainMirrorPipe();

            if (IDS_AppData.MirrorDeadlineMs != 0)
            {
                uint64 nowMs = IDS_GetNowMs();
                /* nowMs < MirrorStartMs guards a backward sim-time step: if
                ** the clock jumped back, disable rather than run forever. */
                if (nowMs >= IDS_AppData.MirrorDeadlineMs || nowMs < IDS_AppData.MirrorStartMs)
                {
                    IDS_DisableMirror("mirror window elapsed");
                }
            }
        }
    }

    if (IDS_AppData.MirrorActive)
    {
        IDS_DisableMirror("app exiting");
    }

    CFE_ES_PerfLogExit(IDS_PERF_ID);
    CFE_ES_ExitApp(IDS_AppData.RunStatus);
}

/*
** Initialize application
*/
int32 IDS_AppInit(void)
{
    int32 status = OS_SUCCESS;

    IDS_AppData.RunStatus = CFE_ES_RunStatus_APP_RUN;

    status = CFE_EVS_Register(NULL, 0, CFE_EVS_EventFilter_BINARY);
    if (status != CFE_SUCCESS)
    {
        CFE_ES_WriteToSysLog("IDS: Error registering for event services: 0x%08X\n", (unsigned int)status);
        return status;
    }

    status = CFE_SB_CreatePipe(&IDS_AppData.CmdPipe, IDS_PIPE_DEPTH, "IDS_CMD_PIPE");
    if (status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(IDS_PIPE_ERR_EID, CFE_EVS_EventType_ERROR, "Error Creating SB Pipe,RC=0x%08X",
                          (unsigned int)status);
        return status;
    }

    /*
    ** Subscribe to our own ground commands
    */
    status = CFE_SB_Subscribe(CFE_SB_ValueToMsgId(IDS_CMD_MID), IDS_AppData.CmdPipe);
    if (status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(IDS_SUB_CMD_ERR_EID, CFE_EVS_EventType_ERROR,
                          "Error Subscribing to Gnd Cmds, MID=0x%04X, RC=0x%08X", IDS_CMD_MID, (unsigned int)status);
        return status;
    }

    /*
    ** Subscribe to the EVS event channel - this alone gives us every
    ** informational/error/critical event any app in the system raises.
    */
    status = CFE_SB_Subscribe(CFE_SB_ValueToMsgId(CFE_EVS_LONG_EVENT_MSG_MID), IDS_AppData.CmdPipe);
    if (status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(IDS_SUB_EVS_ERR_EID, CFE_EVS_EventType_ERROR,
                          "Error Subscribing to EVS events, MID=0x%04X, RC=0x%08X", CFE_EVS_LONG_EVENT_MSG_MID,
                          (unsigned int)status);
        return status;
    }

    /*
    ** The bus mirror is NOT started here - it is off at boot and enabled at
    ** runtime by IDS_SET_MIRROR_CC (see IDS_EnableMirror). That keeps IDS a
    ** quiet, well-behaved app by default; deep inspection is opt-in and
    ** time-bounded.
    */

    /*
    ** Register and load the baseline table. The working copy the app
    ** actually reads/writes every cycle is IDS_AppData.WorkingBaseline;
    ** BaselinePtr (from CFE_TBL_GetAddress) is only touched by
    ** IDS_SaveBaseline()/IDS_LoadBaseline() to sync with table services so
    ** the ground can dump/load it like any other cFS table.
    */
    status = CFE_TBL_Register(&IDS_AppData.BaselineTableHandle, "BaselineTbl", sizeof(IDS_BaselineTbl_t),
                              CFE_TBL_OPT_DEFAULT, IDS_ValidateBaselineTbl);
    if (status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(IDS_TBL_REG_ERR_EID, CFE_EVS_EventType_ERROR, "Error Registering Baseline Table,RC=0x%08X",
                          (unsigned int)status);
        return status;
    }

    /*
    ** Loading the default table file is best-effort, not required: its
    ** all-zero "nothing learned yet" content is exactly what
    ** IDS_Baseline_Init() below already produces in memory. A missing file
    ** on first boot (before any IDS_SAVE_BASELINE_CC has ever run) is
    ** expected, not fatal - the app continues with the in-memory default
    ** either way.
    */
    status = CFE_TBL_Load(IDS_AppData.BaselineTableHandle, CFE_TBL_SRC_FILE, IDS_BASELINE_FILENAME);
    if (status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(IDS_TBL_LOAD_INF_EID, CFE_EVS_EventType_INFORMATION,
                          "No baseline table file to load yet (RC=0x%08X), starting with an empty baseline",
                          (unsigned int)status);
    }

    IDS_Baseline_Init(&IDS_AppData.WorkingBaseline);

    CFE_MSG_Init(CFE_MSG_PTR(IDS_AppData.HkTelemetryPkt.TlmHeader), CFE_SB_ValueToMsgId(IDS_HK_TLM_MID),
                 IDS_HK_TLM_LNGTH);
    CFE_MSG_Init(CFE_MSG_PTR(IDS_AppData.AnomalyPkt.TlmHeader), CFE_SB_ValueToMsgId(IDS_ANOMALY_TLM_MID),
                 IDS_ANOMALY_TLM_LNGTH);

    IDS_ResetCounters();

    IDS_AppData.Mode                 = IDS_MODE_LEARN;
    IDS_AppData.MsgsSinceHk           = 0;
    IDS_AppData.RateRatioThreshold    = IDS_DEFAULT_RATE_RATIO;
    IDS_AppData.SilenceTimeoutMs      = IDS_DEFAULT_SILENCE_TIMEOUT_MS;
    IDS_AppData.CmdErrSpikeThreshold  = IDS_DEFAULT_CMD_ERR_SPIKE;
    IDS_AppData.HaveLastCiCmdErrCount = false;
    IDS_AppData.MirrorActive          = false;
    IDS_AppData.MirrorPipeValid       = false;
    IDS_AppData.MirrorStartMs         = 0;
    IDS_AppData.MirrorDeadlineMs      = 0;
    IDS_AppData.MirrorCount           = 0;
    memset(IDS_AppData.MirrorTable, 0, sizeof(IDS_AppData.MirrorTable));

    status = CFE_EVS_SendEvent(IDS_STARTUP_INF_EID, CFE_EVS_EventType_INFORMATION,
                               "IDS App Initialized in LEARN mode. Version %d.%d.%d.%d", IDS_MAJOR_VERSION,
                               IDS_MINOR_VERSION, IDS_REVISION, IDS_MISSION_REV);
    if (status != CFE_SUCCESS)
    {
        CFE_ES_WriteToSysLog("IDS: Error sending initialization event: 0x%08X\n", (unsigned int)status);
    }
    return status;
}

/*
** Current time in milliseconds, for interval/rate/silence math and the mirror
** window deadline.
**
** Built from CFE_TIME_GetTime(): its Seconds field is honest, tone-driven
** mission seconds. We deliberately do NOT use OS_GetLocalTime here - in this
** NOS build the OSAL clock returns simulated time with non-standard tick
** scaling (OS_TimeGetTotalMilliseconds mis-reads it), which made a 30 s mirror
** window expire in ~1 s. Seconds*1000 plus the subsecond fraction gives real
** milliseconds. Callers guard against the backward step CFE_TIME can take
** across a sim restart (see the NowMs >= LastTimeMs checks).
*/
uint64 IDS_GetNowMs(void)
{
    CFE_TIME_SysTime_t Now = CFE_TIME_GetTime();

    /* Subseconds is a 32-bit fraction of one second: ms = Subseconds / (2^32/1000) */
    return ((uint64)Now.Seconds * 1000) + ((uint64)Now.Subseconds / 4294967);
}

/*
** Process packets received on the IDS command pipe.
**
** The default case here is deliberately NOT an error path (see file header
** comment) - anything that isn't our own command MID, the EVS event MID, or
** the SB subscription-report MID is bus traffic we mirror-subscribed to on
** purpose, and gets routed to IDS_ProcessMirroredMessage().
*/
void IDS_ProcessCommandPacket(void)
{
    CFE_SB_MsgId_t MsgId = CFE_SB_INVALID_MSG_ID;
    CFE_MSG_GetMsgId(IDS_AppData.MsgPtr, &MsgId);

    switch (CFE_SB_MsgIdToValue(MsgId))
    {
        case IDS_CMD_MID:
            IDS_ProcessGroundCommand();
            break;

        case CFE_EVS_LONG_EVENT_MSG_MID:
            IDS_ProcessEvent();
            break;

        case CFE_SB_ONESUB_TLM_MID:
            IDS_ProcessSubscriptionReport();
            break;

        default:
            IDS_ProcessMirroredMessage(MsgId);
            break;
    }
    return;
}

/*
** Process ground commands
*/
void IDS_ProcessGroundCommand(void)
{
    CFE_SB_MsgId_t    MsgId       = CFE_SB_INVALID_MSG_ID;
    CFE_MSG_FcnCode_t CommandCode = 0;

    CFE_MSG_GetMsgId(IDS_AppData.MsgPtr, &MsgId);
    CFE_MSG_GetFcnCode(IDS_AppData.MsgPtr, &CommandCode);

    switch (CommandCode)
    {
        case IDS_NOOP_CC:
            if (IDS_VerifyCmdLength(IDS_AppData.MsgPtr, sizeof(IDS_NoArgs_cmd_t)) == OS_SUCCESS)
            {
                IDS_AppData.HkTelemetryPkt.CommandCount++;
                CFE_EVS_SendEvent(IDS_CMD_NOOP_INF_EID, CFE_EVS_EventType_INFORMATION, "IDS: NOOP command received");
            }
            break;

        case IDS_RESET_COUNTERS_CC:
            if (IDS_VerifyCmdLength(IDS_AppData.MsgPtr, sizeof(IDS_NoArgs_cmd_t)) == OS_SUCCESS)
            {
                IDS_ResetCounters();
            }
            break;

        case IDS_SET_MODE_CC:
            if (IDS_VerifyCmdLength(IDS_AppData.MsgPtr, sizeof(IDS_SetMode_cmd_t)) == OS_SUCCESS)
            {
                IDS_SetMode(((IDS_SetMode_cmd_t *)IDS_AppData.MsgPtr)->Mode);
            }
            break;

        case IDS_SAVE_BASELINE_CC:
            if (IDS_VerifyCmdLength(IDS_AppData.MsgPtr, sizeof(IDS_NoArgs_cmd_t)) == OS_SUCCESS)
            {
                IDS_SaveBaseline();
            }
            break;

        case IDS_LOAD_BASELINE_CC:
            if (IDS_VerifyCmdLength(IDS_AppData.MsgPtr, sizeof(IDS_NoArgs_cmd_t)) == OS_SUCCESS)
            {
                IDS_LoadBaseline();
            }
            break;

        case IDS_DUMP_BASELINE_CC:
            if (IDS_VerifyCmdLength(IDS_AppData.MsgPtr, sizeof(IDS_NoArgs_cmd_t)) == OS_SUCCESS)
            {
                IDS_DumpBaseline();
            }
            break;

        case IDS_CLEAR_BASELINE_CC:
            if (IDS_VerifyCmdLength(IDS_AppData.MsgPtr, sizeof(IDS_NoArgs_cmd_t)) == OS_SUCCESS)
            {
                IDS_ClearBaseline();
            }
            break;

        case IDS_ENABLE_APP_CC:
            if (IDS_VerifyCmdLength(IDS_AppData.MsgPtr, sizeof(IDS_AppFilter_cmd_t)) == OS_SUCCESS)
            {
                IDS_EnableApp(((IDS_AppFilter_cmd_t *)IDS_AppData.MsgPtr)->AppName);
            }
            break;

        case IDS_DISABLE_APP_CC:
            if (IDS_VerifyCmdLength(IDS_AppData.MsgPtr, sizeof(IDS_AppFilter_cmd_t)) == OS_SUCCESS)
            {
                IDS_DisableApp(((IDS_AppFilter_cmd_t *)IDS_AppData.MsgPtr)->AppName);
            }
            break;

        case IDS_SET_THRESHOLD_CC:
            if (IDS_VerifyCmdLength(IDS_AppData.MsgPtr, sizeof(IDS_SetThreshold_cmd_t)) == OS_SUCCESS)
            {
                IDS_SetThreshold(((IDS_SetThreshold_cmd_t *)IDS_AppData.MsgPtr)->DetectorId,
                                 ((IDS_SetThreshold_cmd_t *)IDS_AppData.MsgPtr)->Threshold);
            }
            break;

        case IDS_SET_MIRROR_CC:
            if (IDS_VerifyCmdLength(IDS_AppData.MsgPtr, sizeof(IDS_SetMirror_cmd_t)) == OS_SUCCESS)
            {
                IDS_SetMirror(((IDS_SetMirror_cmd_t *)IDS_AppData.MsgPtr)->Enable,
                              ((IDS_SetMirror_cmd_t *)IDS_AppData.MsgPtr)->DurationSec);
            }
            break;

        default:
            IDS_AppData.HkTelemetryPkt.CommandErrorCount++;
            CFE_EVS_SendEvent(IDS_CMD_ERR_EID, CFE_EVS_EventType_ERROR,
                              "IDS: Invalid command code for packet, MID = 0x%x, cmdCode = 0x%x",
                              CFE_SB_MsgIdToValue(MsgId), CommandCode);
            break;
    }
    return;
}

/*
** Mirror-subscribe to one MID on the dedicated mirror pipe. Skips our own
** MIDs (else our telemetry would loop back at us), de-duplicates, and caps at
** IDS_MAX_TRACKED_MIDS. Silent when already tracked or at capacity - during a
** full-bus replay this is called for 100+ MIDs, so per-MID chatter would just
** flood EVS; the "tracked N MIDs" disable event reports the final count.
*/
static void IDS_MirrorSubscribeMid(CFE_SB_MsgId_t MsgId)
{
    int32 status;
    int   i;

    /*
    ** Skip our own MIDs. This includes ALLSUBS/ONESUB themselves: IDS already
    ** explicitly subscribes to those two directly in IDS_EnableMirror, and
    ** since that subscribe happens BEFORE SEND_PREV_SUBS_CC, IDS's own
    ** ALLSUBS/ONESUB subscriptions are themselves part of the replay this
    ** function processes - without this skip, IDS would try to re-subscribe
    ** to what it's already subscribed to and get a "Duplicate Subscription"
    ** event from CFE_SB for no benefit.
    */
    if (CFE_SB_MsgId_Equal(MsgId, CFE_SB_ValueToMsgId(IDS_HK_TLM_MID)) ||
        CFE_SB_MsgId_Equal(MsgId, CFE_SB_ValueToMsgId(IDS_ANOMALY_TLM_MID)) ||
        CFE_SB_MsgId_Equal(MsgId, CFE_SB_ValueToMsgId(IDS_CMD_MID)) ||
        CFE_SB_MsgId_Equal(MsgId, CFE_SB_ValueToMsgId(CFE_SB_ALLSUBS_TLM_MID)) ||
        CFE_SB_MsgId_Equal(MsgId, CFE_SB_ValueToMsgId(CFE_SB_ONESUB_TLM_MID)))
    {
        return;
    }

    for (i = 0; i < IDS_AppData.MirrorCount; i++)
    {
        if (IDS_AppData.MirrorTable[i].InUse && CFE_SB_MsgId_Equal(IDS_AppData.MirrorTable[i].MsgId, MsgId))
        {
            return; /* already mirrored */
        }
    }

    if (IDS_AppData.MirrorCount >= IDS_MAX_TRACKED_MIDS)
    {
        return; /* capped - reflected in the tracked-count reported at disable */
    }

    /* Mirrored traffic goes to the dedicated mirror pipe, never the command
    ** pipe - that is what keeps IDS responsive under the firehose. */
    status = CFE_SB_Subscribe(MsgId, IDS_AppData.MirrorPipe);
    if (status == CFE_SUCCESS)
    {
        IDS_AppData.MirrorTable[IDS_AppData.MirrorCount].InUse = true;
        IDS_AppData.MirrorTable[IDS_AppData.MirrorCount].MsgId = MsgId;
        IDS_AppData.MirrorCount++;
    }
    else
    {
        CFE_EVS_SendEvent(IDS_MIRROR_SUBSCRIBE_ERR_EID, CFE_EVS_EventType_ERROR,
                          "IDS: could not mirror-subscribe MID 0x%x, RC=0x%08X",
                          CFE_SB_MsgIdToValue(MsgId), (unsigned int)status);
    }
}

/*
** Handle a CFE_SB_ALLSUBS_TLM (0x080D) packet - the BULK reply to
** SEND_PREV_SUBS, carrying up to CFE_SB_SUB_ENTRIES_PER_PKT existing
** subscriptions each (the replay may span several packets). This is how the
** current bus is captured when the mirror is first enabled; ONESUB below only
** carries subscriptions made AFTER that.
*/
void IDS_ProcessAllSubsReport(void)
{
    CFE_SB_AllSubscriptionsTlm_t *AllSubs = (CFE_SB_AllSubscriptionsTlm_t *)IDS_AppData.MsgPtr;
    uint32                        n, count;

    if (!IDS_AppData.MirrorActive || !IDS_AppData.MirrorPipeValid)
    {
        return;
    }

    count = AllSubs->Payload.Entries;
    if (count > CFE_SB_SUB_ENTRIES_PER_PKT)
    {
        count = CFE_SB_SUB_ENTRIES_PER_PKT; /* bound against a malformed count */
    }

    for (n = 0; n < count; n++)
    {
        IDS_MirrorSubscribeMid(AllSubs->Payload.Entry[n].MsgId);
    }
    return;
}

/*
** Handle one CFE_SB_ONESUB_TLM (0x080E) report - a single NEW subscription
** made while the mirror window is open. Unsubscriptions are ignored (staying
** subscribed to an unused MID is harmless).
*/
void IDS_ProcessSubscriptionReport(void)
{
    CFE_SB_SingleSubscriptionTlm_t *SubMsg = (CFE_SB_SingleSubscriptionTlm_t *)IDS_AppData.MsgPtr;

    if (!IDS_AppData.MirrorActive || !IDS_AppData.MirrorPipeValid)
    {
        return;
    }

    if (SubMsg->Payload.SubType != CFE_SB_SUBSCRIPTION)
    {
        return;
    }

    IDS_MirrorSubscribeMid(SubMsg->Payload.MsgId);
    return;
}

/*
** Handle one EVS event: in LEARN mode, add it to the app's profile. In
** MONITOR mode, compare it against the learned profile and raise an
** anomaly if it looks wrong. IDLE mode does nothing.
*/
void IDS_ProcessEvent(void)
{
    CFE_EVS_LongEventTlm_t *EventMsg = (CFE_EVS_LongEventTlm_t *)IDS_AppData.MsgPtr;
    uint64                  NowMs    = IDS_GetNowMs();
    IDS_DetectorResult_t    Result;

    /*
    ** Skip IDS's own events. Since EVS republishes every event (including
    ** IDS's own IDS_ANOMALY_EID) back to every EVS subscriber, and IDS is
    ** one of those subscribers, processing our own events would mean every
    ** anomaly report about some OTHER app also gets evaluated as an event
    ** from "IDS" itself - one that, by construction, was never seen during
    ** LEARN (anomaly events only exist in MONITOR), so it would immediately
    ** flag as unknown and raise another anomaly, which comes back around
    ** and repeats. A monitor should not monitor its own alerting output.
    */
    if (strncmp(EventMsg->Payload.PacketID.AppName, "IDS", CFE_MISSION_MAX_API_LEN) == 0)
    {
        return;
    }

    IDS_AppData.HkTelemetryPkt.EventsProcessedCount++;

    if (IDS_AppData.Mode == IDS_MODE_LEARN)
    {
        bool WasNew;
        IDS_Baseline_FindOrAddApp(&IDS_AppData.WorkingBaseline, EventMsg->Payload.PacketID.AppName, &WasNew);
        if (WasNew)
        {
            CFE_EVS_SendEvent(IDS_NEW_APP_LEARNED_INF_EID, CFE_EVS_EventType_INFORMATION,
                              "IDS: learning new app profile: %s", EventMsg->Payload.PacketID.AppName);
        }
        IDS_Baseline_LearnEvent(&IDS_AppData.WorkingBaseline, EventMsg->Payload.PacketID.AppName,
                                EventMsg->Payload.PacketID.EventID, NowMs);
    }
    else if (IDS_AppData.Mode == IDS_MODE_MONITOR)
    {
        IDS_Detector_CheckEvent(&IDS_AppData.WorkingBaseline, EventMsg->Payload.PacketID.AppName,
                                EventMsg->Payload.PacketID.EventID, NowMs, IDS_AppData.RateRatioThreshold, &Result);
        if (Result.IsAnomaly)
        {
            IDS_RaiseAnomaly(EventMsg->Payload.PacketID.AppName, EventMsg->Payload.PacketID.EventID,
                            Result.AnomalyType, Result.Score, Result.Description);
        }
    }
    return;
}

/*
** Handle any other mirrored bus traffic (not our commands, not an EVS event,
** not a subscription report). Feeds the per-MID rate/silence features, and
** specifically recognizes CI's HK packet to run the uplink reject-spike
** detector - the one detector tied to the actual external attack surface.
*/
void IDS_ProcessMirroredMessage(CFE_SB_MsgId_t MsgId)
{
    uint64 NowMs = IDS_GetNowMs();

    IDS_AppData.HkTelemetryPkt.MirroredMsgCount++;

    if (IDS_AppData.Mode == IDS_MODE_LEARN)
    {
        IDS_Baseline_LearnMid(&IDS_AppData.WorkingBaseline, MsgId, NowMs);
    }

    if (CFE_SB_MsgIdToValue(MsgId) == CI_HK_TLM_MID)
    {
        CI_HkTlm_t *CiHk = (CI_HkTlm_t *)IDS_AppData.MsgPtr;

        if (IDS_AppData.Mode == IDS_MODE_MONITOR && IDS_AppData.HaveLastCiCmdErrCount)
        {
            if (IDS_Detector_CheckCiHk(CiHk->usCmdErrCnt, IDS_AppData.LastCiCmdErrCount,
                                      IDS_AppData.CmdErrSpikeThreshold))
            {
                IDS_RaiseAnomaly("CI", CFE_SB_MsgIdToValue(MsgId), IDS_ANOMALY_CMD_REJECT_SPIKE,
                                (float)(CiHk->usCmdErrCnt - IDS_AppData.LastCiCmdErrCount),
                                "CI rejected-command counter jumped - possible uplink attack");
            }
        }
        IDS_AppData.LastCiCmdErrCount     = CiHk->usCmdErrCnt;
        IDS_AppData.HaveLastCiCmdErrCount = true;
    }
    return;
}

/*
** Drain the dedicated mirror pipe, bounded per call so servicing the firehose
** can never starve command/HK processing in the main loop. Each message is
** either a subscription report (grow the mirror set) or mirrored bus traffic
** (feed the MID-level detectors).
*/
void IDS_DrainMirrorPipe(void)
{
    int            drained = 0;
    int32          status;
    CFE_SB_MsgId_t MsgId = CFE_SB_INVALID_MSG_ID;

    while (drained < IDS_MIRROR_MAX_DRAIN_PER_CYCLE)
    {
        status = CFE_SB_ReceiveBuffer((CFE_SB_Buffer_t **)&IDS_AppData.MsgPtr, IDS_AppData.MirrorPipe, CFE_SB_POLL);
        if (status != CFE_SUCCESS)
        {
            break; /* pipe empty (CFE_SB_NO_MESSAGE) or read error */
        }

        CFE_MSG_GetMsgId(IDS_AppData.MsgPtr, &MsgId);
        if (CFE_SB_MsgIdToValue(MsgId) == CFE_SB_ALLSUBS_TLM_MID)
        {
            IDS_ProcessAllSubsReport(); /* bulk replay of existing subscriptions */
        }
        else if (CFE_SB_MsgIdToValue(MsgId) == CFE_SB_ONESUB_TLM_MID)
        {
            IDS_ProcessSubscriptionReport(); /* a single new subscription */
        }
        else
        {
            IDS_ProcessMirroredMessage(MsgId);
        }
        drained++;
    }
    return;
}

/*
** Ground command dispatch (IDS_SET_MIRROR_CC): enable the mirror for a bounded
** window, or disable it now.
*/
void IDS_SetMirror(uint8 Enable, uint32 DurationSec)
{
    int32 status = CFE_SUCCESS;

    if (Enable)
    {
        status = IDS_EnableMirror(DurationSec);
    }
    else
    {
        IDS_DisableMirror("disabled by command");
    }

    if (status == CFE_SUCCESS)
    {
        IDS_AppData.HkTelemetryPkt.CommandCount++;
    }
    else
    {
        IDS_AppData.HkTelemetryPkt.CommandErrorCount++;
    }
    return;
}

/*
** Turn on the deep bus mirror: stand up the dedicated pipe, subscribe the SB
** subscription-report channel to it, ask SB to enable reporting and replay
** existing subscriptions, and arm the auto-disable deadline. Returns
** CFE_SUCCESS or the failing status; does not touch command counters (the
** IDS_SetMirror caller does that).
*/
int32 IDS_EnableMirror(uint32 DurationSec)
{
    int32                   status;
    CFE_MSG_CommandHeader_t CmdMsg;

    /*
    ** Already on: a second IDS_SET_MIRROR_CC(ENABLE=1) arrived while the
    ** window was still open. This is the ONLY code path that can move the
    ** deadline once set - there is no internal auto-retrigger anywhere else
    ** in this app. Report how much time was actually left, so a duplicate or
    ** re-sent command shows up unambiguously in the event log rather than
    ** looking like the timer misbehaved on its own.
    */
    if (IDS_AppData.MirrorActive)
    {
        uint64 NowMs         = IDS_GetNowMs();
        int32  SecRemaining  = -1; /* -1 = no deadline was set (open-ended window) */

        if (IDS_AppData.MirrorDeadlineMs != 0)
        {
            SecRemaining = (NowMs < IDS_AppData.MirrorDeadlineMs)
                               ? (int32)((IDS_AppData.MirrorDeadlineMs - NowMs) / 1000)
                               : 0;
        }

        IDS_AppData.MirrorStartMs    = NowMs;
        IDS_AppData.MirrorDeadlineMs = (DurationSec > 0) ? (NowMs + (uint64)DurationSec * 1000) : 0;

        CFE_EVS_SendEvent(IDS_MIRROR_ENABLE_INF_EID, CFE_EVS_EventType_INFORMATION,
                          "IDS: mirror ENABLE received while already active (had ~%d s left) - "
                          "window extended to %u s from now",
                          (int)SecRemaining, (unsigned int)DurationSec);
        return CFE_SUCCESS;
    }

    status = CFE_SB_CreatePipe(&IDS_AppData.MirrorPipe, IDS_MIRROR_PIPE_DEPTH, "IDS_MIRROR_PIPE");
    if (status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(IDS_MIRROR_ENABLE_ERR_EID, CFE_EVS_EventType_ERROR,
                          "IDS: mirror enable failed creating pipe, RC=0x%08X", (unsigned int)status);
        return status;
    }
    IDS_AppData.MirrorPipeValid = true;

    /* ALLSUBS carries the bulk replay of existing subscriptions (SEND_PREV_SUBS);
    ** ONESUB carries single new subscriptions made during the window. Need both. */
    status = CFE_SB_Subscribe(CFE_SB_ValueToMsgId(CFE_SB_ALLSUBS_TLM_MID), IDS_AppData.MirrorPipe);
    if (status == CFE_SUCCESS)
    {
        status = CFE_SB_Subscribe(CFE_SB_ValueToMsgId(CFE_SB_ONESUB_TLM_MID), IDS_AppData.MirrorPipe);
    }
    if (status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(IDS_MIRROR_ENABLE_ERR_EID, CFE_EVS_EventType_ERROR,
                          "IDS: mirror enable failed subscribing sub-reports, RC=0x%08X", (unsigned int)status);
        CFE_SB_DeletePipe(IDS_AppData.MirrorPipe);
        IDS_AppData.MirrorPipeValid = false;
        return status;
    }

    IDS_AppData.MirrorActive = true;
    IDS_AppData.MirrorCount  = 0;
    memset(IDS_AppData.MirrorTable, 0, sizeof(IDS_AppData.MirrorTable));

    /* Turn on system-wide subscription reporting and replay existing subs -
    ** the replay burst lands on the dedicated mirror pipe, not the cmd pipe. */
    CFE_MSG_Init((CFE_MSG_Message_t *)&CmdMsg, CFE_SB_ValueToMsgId(CFE_SB_SUB_RPT_CTRL_MID), sizeof(CmdMsg));
    CFE_MSG_SetFcnCode((CFE_MSG_Message_t *)&CmdMsg, CFE_SB_ENABLE_SUB_REPORTING_CC);
    CFE_SB_TransmitMsg((CFE_MSG_Message_t *)&CmdMsg, true);
    CFE_MSG_SetFcnCode((CFE_MSG_Message_t *)&CmdMsg, CFE_SB_SEND_PREV_SUBS_CC);
    CFE_SB_TransmitMsg((CFE_MSG_Message_t *)&CmdMsg, true);

    IDS_AppData.MirrorStartMs    = IDS_GetNowMs();
    IDS_AppData.MirrorDeadlineMs =
        (DurationSec > 0) ? (IDS_AppData.MirrorStartMs + (uint64)DurationSec * 1000) : 0;

    CFE_EVS_SendEvent(IDS_MIRROR_ENABLE_INF_EID, CFE_EVS_EventType_INFORMATION,
                      "IDS: bus mirror ENABLED, duration=%u s (0=until disabled)", (unsigned int)DurationSec);
    return CFE_SUCCESS;
}

/*
** Turn off the deep bus mirror: stop system-wide reporting, then delete the
** mirror pipe (which auto-unsubscribes ONESUB and every mirrored MID at once).
** Safe to call when already off. Does not touch command counters.
*/
void IDS_DisableMirror(const char *Reason)
{
    CFE_MSG_CommandHeader_t CmdMsg;

    if (!IDS_AppData.MirrorActive)
    {
        return;
    }

    CFE_MSG_Init((CFE_MSG_Message_t *)&CmdMsg, CFE_SB_ValueToMsgId(CFE_SB_SUB_RPT_CTRL_MID), sizeof(CmdMsg));
    CFE_MSG_SetFcnCode((CFE_MSG_Message_t *)&CmdMsg, CFE_SB_DISABLE_SUB_REPORTING_CC);
    CFE_SB_TransmitMsg((CFE_MSG_Message_t *)&CmdMsg, true);

    if (IDS_AppData.MirrorPipeValid)
    {
        CFE_SB_DeletePipe(IDS_AppData.MirrorPipe);
        IDS_AppData.MirrorPipeValid = false;
    }

    IDS_AppData.MirrorActive     = false;
    IDS_AppData.MirrorDeadlineMs = 0;

    CFE_EVS_SendEvent(IDS_MIRROR_DISABLE_INF_EID, CFE_EVS_EventType_INFORMATION,
                      "IDS: bus mirror DISABLED (%s), had tracked %u MIDs",
                      (Reason != NULL) ? Reason : "", (unsigned int)IDS_AppData.MirrorCount);

    IDS_AppData.MirrorCount = 0;
    return;
}

/*
** Walk the learned app profiles and flag any known, enabled app that has
** gone quiet. Only runs in MONITOR mode - going quiet during LEARN just
** means we have not seen that app do anything yet.
**
** Only meaningful while the bus mirror is ON. With only the EVS event
** channel (mirror off, the default), most apps legitimately emit events just
** occasionally, so "no event in N seconds" is normal, not anomalous - and
** flagging every quiet app at once produces a burst of anomaly packets that
** overflows TO's telemetry pipe. So this detector runs only during a mirror
** window (and only in MONITOR mode).
*/
void IDS_CheckSilence(void)
{
    uint64 NowMs;
    int    i;

    if (!IDS_AppData.MirrorActive || IDS_AppData.Mode != IDS_MODE_MONITOR)
    {
        return;
    }

    NowMs = IDS_GetNowMs();

    for (i = 0; i < IDS_MAX_TRACKED_APPS; i++)
    {
        IDS_AppProfile_t *Profile = &IDS_AppData.WorkingBaseline.AppProfile[i];

        if (IDS_Detector_IsSilent(Profile, NowMs, IDS_AppData.SilenceTimeoutMs))
        {
            IDS_RaiseAnomaly(Profile->AppName, 0, IDS_ANOMALY_APP_SILENT, 1.0,
                            "known app has not emitted an event within the silence timeout");

            /* Reset the clock so we alert once per silence period, not once
            ** per tick until the app speaks again. */
            Profile->LastEventTimeMs = NowMs;
        }
    }
    return;
}

/*
** Fill in and publish the anomaly report, plus a critical EVS event so a
** human watching the live event log sees it immediately.
*/
void IDS_RaiseAnomaly(const char *AppName, uint16 EventOrMid, uint8 AnomalyType, float Score,
                      const char *Description)
{
    IDS_AppData.HkTelemetryPkt.AnomaliesDetectedCount++;

    IDS_AppData.AnomalyPkt.Timestamp = IDS_GetNowMs();
    strncpy(IDS_AppData.AnomalyPkt.SourceAppName, AppName, CFE_MISSION_MAX_API_LEN - 1);
    IDS_AppData.AnomalyPkt.SourceAppName[CFE_MISSION_MAX_API_LEN - 1] = '\0';
    IDS_AppData.AnomalyPkt.SourceEventOrMid                           = EventOrMid;
    IDS_AppData.AnomalyPkt.AnomalyType                                = AnomalyType;
    IDS_AppData.AnomalyPkt.Score                                      = Score;
    strncpy(IDS_AppData.AnomalyPkt.Description, Description, sizeof(IDS_AppData.AnomalyPkt.Description) - 1);
    IDS_AppData.AnomalyPkt.Description[sizeof(IDS_AppData.AnomalyPkt.Description) - 1] = '\0';

    CFE_SB_TimeStampMsg((CFE_MSG_Message_t *)&IDS_AppData.AnomalyPkt);
    CFE_SB_TransmitMsg((CFE_MSG_Message_t *)&IDS_AppData.AnomalyPkt, true);

    CFE_EVS_SendEvent(IDS_ANOMALY_EID, CFE_EVS_EventType_CRITICAL, "IDS: ANOMALY type=%u app=%s score=%.2f - %s",
                      AnomalyType, AppName, (double)Score, Description);
    return;
}

/*
** Report Application Housekeeping
*/
void IDS_ReportHousekeeping(void)
{
    int i;

    IDS_AppData.HkTelemetryPkt.Mode               = IDS_AppData.Mode;
    IDS_AppData.HkTelemetryPkt.MirrorActive        = (IDS_AppData.MirrorActive ? 1 : 0);
    IDS_AppData.HkTelemetryPkt.SubscribedMidCount  = IDS_AppData.MirrorCount;
    IDS_AppData.HkTelemetryPkt.KnownAppCount       = 0;

    for (i = 0; i < IDS_MAX_TRACKED_APPS; i++)
    {
        if (IDS_AppData.WorkingBaseline.AppProfile[i].Recorded)
        {
            IDS_AppData.HkTelemetryPkt.KnownAppCount++;
        }
    }

    CFE_SB_TimeStampMsg((CFE_MSG_Message_t *)&IDS_AppData.HkTelemetryPkt);
    CFE_SB_TransmitMsg((CFE_MSG_Message_t *)&IDS_AppData.HkTelemetryPkt, true);
    return;
}

/*
** Reset all global counter variables. Note this does NOT touch Mode or the
** learned baseline - those are only changed by their own dedicated commands.
*/
void IDS_ResetCounters(void)
{
    IDS_AppData.HkTelemetryPkt.CommandErrorCount      = 0;
    IDS_AppData.HkTelemetryPkt.CommandCount           = 0;
    IDS_AppData.HkTelemetryPkt.EventsProcessedCount    = 0;
    IDS_AppData.HkTelemetryPkt.MirroredMsgCount        = 0;
    IDS_AppData.HkTelemetryPkt.AnomaliesDetectedCount  = 0;

    CFE_EVS_SendEvent(IDS_CMD_RESET_INF_EID, CFE_EVS_EventType_INFORMATION, "IDS: RESET counters command received");
    return;
}

/*
** Switch between LEARN, MONITOR, and IDLE. See ids_app_state_machine design:
** LEARN <-> MONITOR is the only ground-commanded transition; going back to
** LEARN from MONITOR lets the baseline keep adapting instead of staying
** frozen at whatever was learned once.
*/
void IDS_SetMode(uint8 NewMode)
{
    if (NewMode != IDS_MODE_LEARN && NewMode != IDS_MODE_MONITOR && NewMode != IDS_MODE_IDLE)
    {
        IDS_AppData.HkTelemetryPkt.CommandErrorCount++;
        CFE_EVS_SendEvent(IDS_CMD_SET_MODE_ERR_EID, CFE_EVS_EventType_ERROR, "IDS: invalid mode %u", NewMode);
        return;
    }

    IDS_AppData.HkTelemetryPkt.CommandCount++;
    IDS_AppData.Mode = NewMode;
    CFE_EVS_SendEvent(IDS_CMD_SET_MODE_INF_EID, CFE_EVS_EventType_INFORMATION, "IDS: mode set to %u", NewMode);
    return;
}

/*
** Push the working baseline into the CFE_TBL buffer. IDS does not write a
** file itself - once the buffer is updated here, a normal ground "dump
** table" command against the registered name "BaselineTbl" is what
** actually produces a file the operator can inspect or archive.
*/
void IDS_SaveBaseline(void)
{
    int32 status = CFE_TBL_Load(IDS_AppData.BaselineTableHandle, CFE_TBL_SRC_ADDRESS,
                               (const void *)&IDS_AppData.WorkingBaseline);

    if (status == CFE_SUCCESS)
    {
        IDS_AppData.HkTelemetryPkt.CommandCount++;
        IDS_AppData.HkTelemetryPkt.BaselineSaved = 1;
        CFE_EVS_SendEvent(IDS_CMD_SAVE_BASELINE_INF_EID, CFE_EVS_EventType_INFORMATION,
                          "IDS: baseline pushed to table services");
    }
    else
    {
        IDS_AppData.HkTelemetryPkt.CommandErrorCount++;
        CFE_EVS_SendEvent(IDS_CMD_SAVE_BASELINE_ERR_EID, CFE_EVS_EventType_ERROR,
                          "IDS: error saving baseline, RC=0x%08X", (unsigned int)status);
    }
    return;
}

/*
** Reload the working baseline from whatever is currently in the CFE_TBL
** buffer (the last save, or the file loaded at startup).
*/
void IDS_LoadBaseline(void)
{
    int32              status;
    IDS_BaselineTbl_t *TblPtr = NULL;

    status = CFE_TBL_GetAddress((void **)&TblPtr, IDS_AppData.BaselineTableHandle);

    /* CFE_TBL_INFO_UPDATED and CFE_SUCCESS both mean we got a valid pointer */
    if (status == CFE_SUCCESS || status == CFE_TBL_INFO_UPDATED)
    {
        memcpy(&IDS_AppData.WorkingBaseline, TblPtr, sizeof(IDS_BaselineTbl_t));
        IDS_AppData.HkTelemetryPkt.CommandCount++;
        CFE_EVS_SendEvent(IDS_CMD_LOAD_BASELINE_INF_EID, CFE_EVS_EventType_INFORMATION,
                          "IDS: baseline loaded from table services");
        CFE_TBL_ReleaseAddress(IDS_AppData.BaselineTableHandle);
    }
    else
    {
        IDS_AppData.HkTelemetryPkt.CommandErrorCount++;
        CFE_EVS_SendEvent(IDS_CMD_LOAD_BASELINE_ERR_EID, CFE_EVS_EventType_ERROR,
                          "IDS: error loading baseline, RC=0x%08X", (unsigned int)status);
    }
    return;
}

/*
** Write the current baseline out to a file, in one IDS command. IDS still
** does no file I/O itself - it (1) pushes the live working baseline into the
** table buffer and manages it so the ACTIVE buffer is current, then (2) sends
** a cFE Table Services DUMP command (to CFE_TBL_CMD_MID) that makes the TBL
** app write the active buffer to IDS_BASELINE_FILENAME. Since that path is
** also what IDS loads at startup, the dumped file persists the baseline
** across a reset.
*/
void IDS_DumpBaseline(void)
{
    int32             status;
    CFE_TBL_DumpCmd_t DumpCmd;

    /* Step 1: make the table's active buffer match the live working baseline */
    status = CFE_TBL_Load(IDS_AppData.BaselineTableHandle, CFE_TBL_SRC_ADDRESS,
                          (const void *)&IDS_AppData.WorkingBaseline);
    if (status != CFE_SUCCESS)
    {
        IDS_AppData.HkTelemetryPkt.CommandErrorCount++;
        CFE_EVS_SendEvent(IDS_CMD_DUMP_BASELINE_ERR_EID, CFE_EVS_EventType_ERROR,
                          "IDS: dump failed staging baseline, RC=0x%08X", (unsigned int)status);
        return;
    }
    CFE_TBL_Manage(IDS_AppData.BaselineTableHandle);

    /* Step 2: ask Table Services to write the active buffer to a file */
    memset(&DumpCmd, 0, sizeof(DumpCmd));
    CFE_MSG_Init((CFE_MSG_Message_t *)&DumpCmd, CFE_SB_ValueToMsgId(CFE_TBL_CMD_MID), sizeof(DumpCmd));
    CFE_MSG_SetFcnCode((CFE_MSG_Message_t *)&DumpCmd, CFE_TBL_DUMP_CC);

    DumpCmd.Payload.ActiveTableFlag = CFE_TBL_BufferSelect_ACTIVE;
    strncpy(DumpCmd.Payload.TableName, "IDS.BaselineTbl", sizeof(DumpCmd.Payload.TableName) - 1);
    strncpy(DumpCmd.Payload.DumpFilename, IDS_BASELINE_FILENAME, sizeof(DumpCmd.Payload.DumpFilename) - 1);

    CFE_SB_TimeStampMsg((CFE_MSG_Message_t *)&DumpCmd);
    CFE_SB_TransmitMsg((CFE_MSG_Message_t *)&DumpCmd, true);

    IDS_AppData.HkTelemetryPkt.CommandCount++;
    IDS_AppData.HkTelemetryPkt.BaselineSaved = 1;
    CFE_EVS_SendEvent(IDS_CMD_DUMP_BASELINE_INF_EID, CFE_EVS_EventType_INFORMATION,
                      "IDS: baseline dump requested to %s (table IDS.BaselineTbl)", IDS_BASELINE_FILENAME);
    return;
}

/*
** Wipe the learned baseline and start over. Does not touch Mode - typically
** followed by a ground procedure that also sets mode back to LEARN.
*/
void IDS_ClearBaseline(void)
{
    IDS_Baseline_Init(&IDS_AppData.WorkingBaseline);
    IDS_AppData.HkTelemetryPkt.CommandCount++;
    IDS_AppData.HkTelemetryPkt.BaselineSaved = 0;
    CFE_EVS_SendEvent(IDS_CMD_CLEAR_BASELINE_INF_EID, CFE_EVS_EventType_INFORMATION, "IDS: baseline cleared");
    return;
}

/*
** Exclude/include one app's events from detection (not from learning - a
** disabled app is still learned, in case it is re-enabled later).
*/
void IDS_EnableApp(const char *AppName)
{
    IDS_AppProfile_t *Profile = IDS_Baseline_FindApp(&IDS_AppData.WorkingBaseline, AppName);

    if (Profile == NULL)
    {
        IDS_AppData.HkTelemetryPkt.CommandErrorCount++;
        CFE_EVS_SendEvent(IDS_CMD_APP_FILTER_ERR_EID, CFE_EVS_EventType_ERROR, "IDS: unknown app %s", AppName);
        return;
    }

    Profile->Enabled = true;
    IDS_AppData.HkTelemetryPkt.CommandCount++;
    CFE_EVS_SendEvent(IDS_CMD_APP_FILTER_INF_EID, CFE_EVS_EventType_INFORMATION, "IDS: detection enabled for %s",
                      AppName);
    return;
}

void IDS_DisableApp(const char *AppName)
{
    IDS_AppProfile_t *Profile = IDS_Baseline_FindApp(&IDS_AppData.WorkingBaseline, AppName);

    if (Profile == NULL)
    {
        IDS_AppData.HkTelemetryPkt.CommandErrorCount++;
        CFE_EVS_SendEvent(IDS_CMD_APP_FILTER_ERR_EID, CFE_EVS_EventType_ERROR, "IDS: unknown app %s", AppName);
        return;
    }

    Profile->Enabled = false;
    IDS_AppData.HkTelemetryPkt.CommandCount++;
    CFE_EVS_SendEvent(IDS_CMD_APP_FILTER_INF_EID, CFE_EVS_EventType_INFORMATION, "IDS: detection disabled for %s",
                      AppName);
    return;
}

/*
** Update one detector's sensitivity. See ids_msg.h for what Threshold means
** for each DetectorId.
*/
void IDS_SetThreshold(uint8 DetectorId, float Threshold)
{
    switch (DetectorId)
    {
        case IDS_DETECTOR_RATE:
            IDS_AppData.RateRatioThreshold = (double)Threshold;
            break;

        case IDS_DETECTOR_SILENCE:
            IDS_AppData.SilenceTimeoutMs = (uint32)Threshold;
            break;

        case IDS_DETECTOR_CMD_REJECT:
            IDS_AppData.CmdErrSpikeThreshold = (uint8)Threshold;
            break;

        default:
            IDS_AppData.HkTelemetryPkt.CommandErrorCount++;
            CFE_EVS_SendEvent(IDS_CMD_THRESHOLD_ERR_EID, CFE_EVS_EventType_ERROR, "IDS: unknown detector id %u",
                              DetectorId);
            return;
    }

    IDS_AppData.HkTelemetryPkt.CommandCount++;
    CFE_EVS_SendEvent(IDS_CMD_THRESHOLD_INF_EID, CFE_EVS_EventType_INFORMATION,
                      "IDS: detector %u threshold set to %f", DetectorId, (double)Threshold);
    return;
}

/*
** Verify command packet length matches expected
*/
int32 IDS_VerifyCmdLength(CFE_MSG_Message_t *msg, uint16 expected_length)
{
    int32             status        = OS_SUCCESS;
    CFE_SB_MsgId_t    msg_id        = CFE_SB_INVALID_MSG_ID;
    CFE_MSG_FcnCode_t cmd_code      = 0;
    size_t            actual_length = 0;

    CFE_MSG_GetSize(msg, &actual_length);
    if (expected_length != actual_length)
    {
        CFE_MSG_GetMsgId(msg, &msg_id);
        CFE_MSG_GetFcnCode(msg, &cmd_code);

        CFE_EVS_SendEvent(IDS_LEN_ERR_EID, CFE_EVS_EventType_ERROR,
                          "Invalid msg length: ID = 0x%X,  CC = %d, Len = %ld, Expected = %d",
                          CFE_SB_MsgIdToValue(msg_id), cmd_code, actual_length, expected_length);

        status = OS_ERROR;
        IDS_AppData.HkTelemetryPkt.CommandErrorCount++;
    }
    return status;
}
