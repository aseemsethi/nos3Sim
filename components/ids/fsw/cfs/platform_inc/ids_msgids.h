/*******************************************************************************
** File:
**   ids_msgids.h
**
** Purpose:
**  Define IDS Message IDs
**
*******************************************************************************/
#ifndef _IDS_MSGIDS_H_
#define _IDS_MSGIDS_H_

/*
** CCSDS V1 Command Message IDs (MID) must be 0x18xx
** 0x18FE is free: last allocated component command MID is SYN at 0x18FD
*/
#define IDS_CMD_MID 0x18FE

/*
** CCSDS V1 Telemetry Message IDs must be 0x08xx
*/
#define IDS_HK_TLM_MID      0x08FE
#define IDS_ANOMALY_TLM_MID 0x08FF

#endif /* _IDS_MSGIDS_H_ */
