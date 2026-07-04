/*******************************************************************************
** File:
**   ids_events.h
**
** Purpose:
**  Define IDS application event IDs
**
*******************************************************************************/
#ifndef _IDS_EVENTS_H_
#define _IDS_EVENTS_H_

/* Standard app event IDs */
#define IDS_RESERVED_EID        0
#define IDS_STARTUP_INF_EID     1
#define IDS_LEN_ERR_EID         2
#define IDS_PIPE_ERR_EID        3
#define IDS_SUB_CMD_ERR_EID     4
#define IDS_SUB_ONESUB_ERR_EID  5
#define IDS_SUB_EVS_ERR_EID     6
#define IDS_PROCESS_CMD_ERR_EID 7
#define IDS_TBL_REG_ERR_EID     8
#define IDS_TBL_LOAD_INF_EID    9

/* Standard command event IDs */
#define IDS_CMD_ERR_EID               10
#define IDS_CMD_NOOP_INF_EID          11
#define IDS_CMD_RESET_INF_EID         12
#define IDS_CMD_SET_MODE_INF_EID      13
#define IDS_CMD_SET_MODE_ERR_EID      14
#define IDS_CMD_SAVE_BASELINE_INF_EID 15
#define IDS_CMD_SAVE_BASELINE_ERR_EID 16
#define IDS_CMD_LOAD_BASELINE_INF_EID 17
#define IDS_CMD_LOAD_BASELINE_ERR_EID 18
#define IDS_CMD_CLEAR_BASELINE_INF_EID 19
#define IDS_CMD_APP_FILTER_INF_EID    20
#define IDS_CMD_APP_FILTER_ERR_EID    21
#define IDS_CMD_THRESHOLD_INF_EID     22
#define IDS_CMD_THRESHOLD_ERR_EID     23

/* Bus mirroring event IDs */
#define IDS_MIRROR_SUBSCRIBE_ERR_EID 30
#define IDS_NEW_APP_LEARNED_INF_EID  31
#define IDS_BASELINE_FULL_ERR_EID    32
#define IDS_MIRROR_ENABLE_INF_EID    33
#define IDS_MIRROR_ENABLE_ERR_EID    34
#define IDS_MIRROR_DISABLE_INF_EID   35

/* Baseline dump-to-file event IDs */
#define IDS_CMD_DUMP_BASELINE_INF_EID 36
#define IDS_CMD_DUMP_BASELINE_ERR_EID 37

/* Detection event IDs */
#define IDS_ANOMALY_EID 40 /* CRITICAL: raised for every detected anomaly */

#endif /* _IDS_EVENTS_H_ */
