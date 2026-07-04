/*******************************************************************************
** File:
**   ids_platform_cfg.h
**
** Purpose:
**  Define IDS Platform Configuration Parameters
**
*******************************************************************************/
#ifndef _IDS_PLATFORM_CFG_H_
#define _IDS_PLATFORM_CFG_H_

/*
** Default IDS Configuration
*/
#ifndef IDS_CFG

/* Command/HK pipe depth. IDS's steady-state input on this pipe is only EVS
** events plus its own commands, so this is comfortably deep. Capped at this
** mission's OSAL limit (OS_QUEUE_MAX_DEPTH=50; CFE_SB_CreatePipe rejects
** anything deeper and the app fails to start). The firehose never touches
** this pipe - it has its own (see IDS_MIRROR_PIPE_DEPTH). */
#define IDS_PIPE_DEPTH 50

/*
** Runtime bus mirror ("deep inspection"). Enabled on command
** (IDS_SET_MIRROR_CC) for a bounded window, OFF by default. When on, IDS
** turns on system-wide SB subscription reporting and mirror-subscribes to
** every MID on the bus - powerful for MID-level anomaly detection, but it
** generates a ONESUB report storm that loads TO's telemetry pipe. Two
** safeguards keep it from destabilizing the system:
**   1. All mirror traffic lands on a SEPARATE pipe, so the command/HK pipe
**      stays responsive and IDS can always receive the disable command.
**   2. A commanded duration auto-disables it, bounding storm exposure.
*/

/* Dedicated firehose pipe depth (capped at OS_QUEUE_MAX_DEPTH). */
#define IDS_MIRROR_PIPE_DEPTH 50

/* Max mirror messages drained per main-loop iteration, so servicing the
** firehose can never starve command/HK processing. */
#define IDS_MIRROR_MAX_DRAIN_PER_CYCLE 32

/* Default baseline table file, loaded at startup and target of
** IDS_SAVE_BASELINE_CC / IDS_LOAD_BASELINE_CC via CFE_TBL */
#define IDS_BASELINE_FILENAME "/cf/ids_baseline_tbl.tbl"

/* Pipe receive timeout in ms. This is the PRIMARY HK cadence driver: each
** time the pipe idles this long, IDS publishes HK and runs the silence check.
** With the bus mirror off (default) IDS's pipe idles regularly, so HK
** publishes at roughly this rate. Chosen over a clock delta on purpose - the
** only clocks available here are NOS simulated time (see IDS_GetNowMs). */
#define IDS_SB_TIMEOUT_MS 1000

/* Fallback HK trigger: also publish HK after this many processed messages,
** so a sustained burst of EVS traffic (pipe never idling) still gets HK out. */
#define IDS_HK_MSG_INTERVAL 64

/* Bounds for the in-memory baseline (fixed size, no dynamic allocation).
** MIDS is sized to hold most of a full bus - a complete NOS3 system has 100+
** distinct subscriptions once the ALLSUBS replay is captured. Note this also
** sizes the persisted baseline table, so changing it changes the .tbl size. */
#define IDS_MAX_TRACKED_APPS   32
#define IDS_MAX_TRACKED_MIDS   128
#define IDS_MAX_EVENTS_PER_APP 16

/* Default detector sensitivities, overridable on orbit via IDS_SET_THRESHOLD_CC */

/* DETECTOR_RATE: flag an app+event if its instantaneous interval is this many
** times faster than the learned average interval for that app+event */
#define IDS_DEFAULT_RATE_RATIO 5.0

/* DETECTOR_SILENCE: flag a known/enabled app that has not emitted an event in
** this many milliseconds */
#define IDS_DEFAULT_SILENCE_TIMEOUT_MS 60000

/* DETECTOR_CMD_REJECT: flag a jump in CI's rejected-command counter of at
** least this many counts between two consecutive CI HK packets */
#define IDS_DEFAULT_CMD_ERR_SPIKE 5

/* Note: Debug flag disabled (commented out) by default */
//#define IDS_CFG_DEBUG

#endif

#endif /* _IDS_PLATFORM_CFG_H_ */
