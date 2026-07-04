/*******************************************************************************
** File: ids_app.h
**
** Purpose:
**   This is the main header file for the IDS (bus anomaly detection /
**   intrusion detection) application.
**
*******************************************************************************/
#ifndef _IDS_APP_H_
#define _IDS_APP_H_

/*
** Include Files
*/
#include "cfe.h"
#include "ids_events.h"
#include "ids_platform_cfg.h"
#include "ids_perfids.h"
#include "ids_msg.h"
#include "ids_msgids.h"
#include "ids_version.h"
#include "ids_baseline.h"
#include "ids_detector.h"

/*
** Tracks which MIDs this app has already issued CFE_SB_Subscribe() for as
** a result of mirroring CFE_SB_ONESUB_TLM_MID reports. This is deliberately
** separate from the learned baseline (IDS_BaselineTbl_t) - this is just
** "have I subscribed", the baseline is "what does normal look like".
*/
typedef struct
{
    bool           InUse;
    CFE_SB_MsgId_t MsgId;

} IDS_MirrorEntry_t;

/*
** IDS global data structure
*/
typedef struct
{
    /*
    ** Telemetry packets published by this app
    */
    IDS_Hk_tlm_t         HkTelemetryPkt;
    IDS_AnomalyRpt_tlm_t AnomalyPkt;

    /*
    ** Operational data - not reported in housekeeping
    */
    CFE_MSG_Message_t *MsgPtr;
    CFE_SB_PipeId_t    CmdPipe;
    uint32             RunStatus;

    /*
    ** Current mode: IDS_MODE_LEARN, IDS_MODE_MONITOR, or IDS_MODE_IDLE
    */
    uint8 Mode;

    /*
    ** Baseline table (registered with CFE_TBL so it can be dumped/loaded
    ** from the ground and survive a reset)
    */
    CFE_TBL_Handle_t BaselineTableHandle;

    /*
    ** Working baseline. LEARN/MONITOR update and read this copy directly;
    ** IDS_SAVE_BASELINE_CC / IDS_LOAD_BASELINE_CC sync it with the CFE_TBL
    ** buffer via CFE_TBL_Load(..., CFE_TBL_SRC_ADDRESS, ...) and
    ** CFE_TBL_GetAddress() respectively.
    */
    IDS_BaselineTbl_t WorkingBaseline;

    /*
    ** Runtime bus mirror ("deep inspection"), enabled on command for a
    ** bounded window. The firehose and the system-wide subscription-report
    ** storm land on a SEPARATE pipe (MirrorPipe) so the command/HK pipe stays
    ** responsive - IDS can always receive the disable command and keep
    ** publishing HK even while mirroring.
    */
    bool               MirrorActive;
    CFE_SB_PipeId_t    MirrorPipe;
    bool               MirrorPipeValid;   /* MirrorPipe currently created */
    uint64             MirrorStartMs;     /* sim time the window began */
    uint64             MirrorDeadlineMs;  /* sim time to auto-disable; 0 = no deadline */
    IDS_MirrorEntry_t  MirrorTable[IDS_MAX_TRACKED_MIDS];
    uint16             MirrorCount;

    /*
    ** Detector sensitivities, overridable via IDS_SET_THRESHOLD_CC
    */
    double RateRatioThreshold;
    uint32 SilenceTimeoutMs;
    uint8  CmdErrSpikeThreshold;

    /*
    ** Cross-app correlation state for the CI reject-spike detector
    */
    uint8 LastCiCmdErrCount;
    bool  HaveLastCiCmdErrCount;

    /*
    ** HK cadence is driven by the pipe timeout (primary) with a
    ** processed-message-count fallback (this counter) - NOT by any clock,
    ** since the only clocks available here are NOS simulated time.
    */
    uint32 MsgsSinceHk;

} IDS_AppData_t;

/*
** Exported Data
** Extern the global struct in the header for the Unit Test Framework (UTF).
*/
extern IDS_AppData_t IDS_AppData;

/*
** Local function prototypes.
*/
void  IDS_AppMain(void);
int32 IDS_AppInit(void);
void  IDS_ProcessCommandPacket(void);
void  IDS_ProcessGroundCommand(void);
void  IDS_ProcessSubscriptionReport(void);
void  IDS_ProcessAllSubsReport(void);
void  IDS_ProcessEvent(void);
void  IDS_ProcessMirroredMessage(CFE_SB_MsgId_t MsgId);
void  IDS_DrainMirrorPipe(void);
void  IDS_SetMirror(uint8 Enable, uint32 DurationSec);
int32 IDS_EnableMirror(uint32 DurationSec);
void  IDS_DisableMirror(const char *Reason);
void  IDS_CheckSilence(void);
void  IDS_ReportHousekeeping(void);
void  IDS_ResetCounters(void);
void  IDS_SetMode(uint8 NewMode);
void  IDS_SaveBaseline(void);
void  IDS_LoadBaseline(void);
void  IDS_DumpBaseline(void);
void  IDS_ClearBaseline(void);
void  IDS_EnableApp(const char *AppName);
void  IDS_DisableApp(const char *AppName);
void  IDS_SetThreshold(uint8 DetectorId, float Threshold);
void  IDS_RaiseAnomaly(const char *AppName, uint16 EventOrMid, uint8 AnomalyType, float Score,
                       const char *Description);
uint64 IDS_GetNowMs(void);
int32 IDS_VerifyCmdLength(CFE_MSG_Message_t *msg, uint16 expected_length);

#endif /* _IDS_APP_H_ */
