/*******************************************************************************
** File: ids_msg.h
**
** Purpose:
**  Define IDS application commands and telemetry messages
**
*******************************************************************************/
#ifndef _IDS_MSG_H_
#define _IDS_MSG_H_

#include "cfe.h"

/*
** Ground Command Codes
*/
#define IDS_NOOP_CC           0
#define IDS_RESET_COUNTERS_CC 1
#define IDS_SET_MODE_CC       2 /* payload: IDS_SetMode_cmd_t */
#define IDS_SAVE_BASELINE_CC  3 /* pushes working baseline into the CFE_TBL buffer */
#define IDS_LOAD_BASELINE_CC  4 /* reloads working baseline from the CFE_TBL buffer */
#define IDS_CLEAR_BASELINE_CC 5 /* wipes the learned baseline, starts over */
#define IDS_ENABLE_APP_CC     6 /* payload: IDS_AppFilter_cmd_t */
#define IDS_DISABLE_APP_CC    7 /* payload: IDS_AppFilter_cmd_t */
#define IDS_SET_THRESHOLD_CC  8 /* payload: IDS_SetThreshold_cmd_t */
#define IDS_SET_MIRROR_CC     9 /* payload: IDS_SetMirror_cmd_t - runtime deep bus mirror */
#define IDS_DUMP_BASELINE_CC 10 /* no args - writes the baseline to a file via cFE Table Services */

/*
** IDS_SetMode_cmd_t.Mode values
*/
#define IDS_MODE_LEARN   0 /* mirror the bus, build the baseline, do not alert */
#define IDS_MODE_MONITOR 1 /* mirror the bus, compare against baseline, alert */
#define IDS_MODE_IDLE    2 /* subscriptions stay registered, processing paused */

/*
** IDS_SetThreshold_cmd_t.DetectorId values
** Meaning of the accompanying float Threshold depends on which detector:
**   RATE:       ratio of learned-average-interval to live-interval that
**               triggers a flood call (bigger = more tolerant)
**   SILENCE:    milliseconds of inactivity from a known app before it is
**               flagged silent
**   CMD_REJECT: jump in CI's rejected-command counter between two HK
**               packets that triggers a call
*/
#define IDS_DETECTOR_RATE       0
#define IDS_DETECTOR_SILENCE    1
#define IDS_DETECTOR_CMD_REJECT 2

/*
** IDS_AnomalyRpt_tlm_t.AnomalyType values
*/
#define IDS_ANOMALY_UNKNOWN_APP      0 /* event from an app with no learned profile */
#define IDS_ANOMALY_UNKNOWN_EVENT    1 /* known app, event ID never seen in learning */
#define IDS_ANOMALY_RATE_FLOOD       2 /* known app+event, arriving far faster than learned */
#define IDS_ANOMALY_APP_SILENT       3 /* known/enabled app has gone quiet */
#define IDS_ANOMALY_CMD_REJECT_SPIKE 4 /* CI rejected-command counter jumped */

/*
** Generic "no arguments" command type definition
** (NOOP, RESET_COUNTERS, SAVE_BASELINE, LOAD_BASELINE, CLEAR_BASELINE)
*/
typedef struct
{
    CFE_MSG_CommandHeader_t CmdHeader;
} IDS_NoArgs_cmd_t;

/*
** IDS set mode command
*/
typedef struct
{
    CFE_MSG_CommandHeader_t CmdHeader;
    uint8                   Mode;
} IDS_SetMode_cmd_t;

/*
** IDS per-app enable/disable monitoring command
*/
typedef struct
{
    CFE_MSG_CommandHeader_t CmdHeader;
    char                    AppName[CFE_MISSION_MAX_API_LEN];
} IDS_AppFilter_cmd_t;

/*
** IDS set detector threshold command
** Threshold is declared before DetectorId so the 4-byte float lands right
** after the (already 4-byte-aligned) 8-byte CmdHeader with no mid-struct
** padding; the compiler still pads 3 bytes after DetectorId to round the
** struct up to a multiple of 4 - the COSMOS command definition mirrors that
** with an explicit trailing pad so the wire length matches sizeof() exactly.
*/
typedef struct
{
    CFE_MSG_CommandHeader_t CmdHeader;
    float                   Threshold;
    uint8                   DetectorId;
} IDS_SetThreshold_cmd_t;

/*
** IDS enable/disable runtime bus mirror command.
** DurationSec (4-byte) is declared before Enable (1-byte) to keep it
** 4-byte aligned right after CmdHeader with no mid-struct padding; the
** COSMOS definition mirrors that with an explicit trailing pad.
*/
typedef struct
{
    CFE_MSG_CommandHeader_t CmdHeader;
    uint32                  DurationSec; /* auto-disable after this many sim-seconds; 0 = until disabled */
    uint8                   Enable;      /* 1 = enable mirror, 0 = disable now */
} IDS_SetMirror_cmd_t;

/*
** IDS housekeeping type definition
*/
typedef struct
{
    CFE_MSG_TelemetryHeader_t TlmHeader;
    uint8                     CommandErrorCount;
    uint8                     CommandCount;
    uint8                     Mode;
    uint8                     MirrorActive;          /* 1 while the runtime bus mirror is on */
    uint16                    SubscribedMidCount;   /* MIDs currently mirrored (0 when mirror off) */
    uint16                    KnownAppCount;         /* apps with a learned profile */
    uint32                    EventsProcessedCount;  /* EVS events processed */
    uint32                    MirroredMsgCount;      /* non-EVS bus traffic processed */
    uint32                    AnomaliesDetectedCount;
    uint8                     BaselineSaved;         /* set after IDS_SAVE_BASELINE_CC */

} __attribute__((packed)) IDS_Hk_tlm_t;
#define IDS_HK_TLM_LNGTH sizeof(IDS_Hk_tlm_t)

/*
** IDS anomaly report telemetry - one packet per detected anomaly
*/
typedef struct
{
    CFE_MSG_TelemetryHeader_t TlmHeader;
    uint32                    Timestamp;
    char                      SourceAppName[CFE_MISSION_MAX_API_LEN];
    uint16                    SourceEventOrMid; /* EVS EventID, or MID for bus-level findings */
    uint8                     AnomalyType;
    float                     Score;
    char                      Description[64];

} __attribute__((packed)) IDS_AnomalyRpt_tlm_t;
#define IDS_ANOMALY_TLM_LNGTH sizeof(IDS_AnomalyRpt_tlm_t)

#endif /* _IDS_MSG_H_ */
