# IDS - NOS3 Component

This repository contains the NOS3 IDS (Intrusion Detection / anomaly
detection) component. Unlike most components, IDS has no `sim` directory -
it has no simulated hardware, it is a pure software-bus observer.

## Overview

IDS is a cFS application that mirrors the entire cFE Software Bus and the
EVS event stream, learns what "normal" looks like per app, and raises an
anomaly when live behavior deviates from what it learned. See the top
level project's architecture discussion for the full design rationale;
this README covers only what is specific to running/operating this app.

It has two channels of visibility into the rest of the system:

* **EVS events (always on)** - it subscribes directly to the shared EVS event
  MID, which every app's `CFE_EVS_SendEvent()` call already routes through.
  This alone gives it app name + event ID + severity + text for everything
  any app raises, and drives the always-available detectors.
* **Bus mirror (on command, time-bounded)** - see below. Enables SB's
  subscription-reporting feature and mirror-subscribes to every MID on the
  bus for MID-level detection. Off by default because it generates a
  subscription-report storm; commanded on for a bounded window when deep
  inspection is needed.

## Deep bus mirror (runtime, on command)

`IDS_SET_MIRROR_CC` turns the bus mirror on for a bounded window
(`DURATION_SEC` sim-seconds; 0 = until explicitly disabled), or off. It is
**off at boot**. While on, IDS enables system-wide SB subscription reporting
(`CFE_SB_ENABLE_SUB_REPORTING_CC` / `CFE_SB_SEND_PREV_SUBS_CC`), mirror-
subscribes to every MID, and runs the MID-level and CI-reject detectors.

Two safeguards keep the resulting report storm from destabilizing telemetry -
lessons learned the hard way during bring-up:

1. **Dedicated pipe.** All mirror traffic and the ONESUB storm land on a
   separate `IDS_MIRROR_PIPE`, never the command/HK pipe. IDS therefore stays
   responsive - it can always receive the disable command and keep publishing
   HK even under the firehose.
2. **Auto-disable.** The commanded duration bounds storm exposure; when it
   elapses, IDS disables system-wide reporting and deletes the mirror pipe
   (which cleanly unsubscribes everything).

`IDS_HK_TLM.MIRROR_ACTIVE` reports whether the mirror is currently on, and
`SUBSCRIBED_MID_COUNT` how many MIDs are being mirrored.

## Modes

Set via `IDS_SET_MODE_CC`:

* `LEARN` (default at startup) - builds the baseline, never alerts.
* `MONITOR` - compares live activity against the baseline, alerts on
  deviation.
* `IDLE` - subscriptions stay registered, processing is paused.

## Detectors

Enabled in `MONITOR` mode, thresholds adjustable via `IDS_SET_THRESHOLD_CC`.

Always available (EVS-driven, no mirror needed):

* **Unknown app / unknown event** - an EVS event from an app, or an event ID
  from a known app, never seen during learning.
* **Rate flood** - a known app+event arriving far faster than its learned
  average interval.

Only while the deep bus mirror is active (they need MID-level visibility):

* **App silent** - a known, enabled app that has gone quiet past its
  learned-silence timeout. Meaningless on EVS alone (apps are legitimately
  quiet), so it runs only during a mirror window.
* **CI command-reject spike** - a jump in CI's rejected-command counter
  between two housekeeping packets. This is the one detector tied to the
  real external attack surface (the uplink) rather than internal bus
  behavior, since the software bus itself has no authentication between
  onboard apps.

## Baseline persistence

The learned baseline lives in `IDS_AppData.WorkingBaseline` in RAM. IDS does
no file I/O itself; persistence goes through cFE Table Services on the
registered table `IDS.BaselineTbl`.

* `IDS_SAVE_BASELINE_CC` - pushes the live baseline into the table buffer (RAM
  only, no file).
* `IDS_DUMP_BASELINE_CC` - one command that stages the live baseline into the
  table *and* has IDS send a cFE `TBL DUMP` command to write it to a file at
  `IDS_BASELINE_FILENAME` (`/cf/ids_base.tbl`, i.e. host
  `fsw/build/exe/cpu1/cf/`). Since IDS auto-loads that path at startup, the
  dumped file persists the baseline across a reset. The basename must stay
  <= 19 characters - this build's OSAL rejects longer ones with
  `OS_FS_ERR_NAME_TOO_LONG` (which is exactly what the original
  `ids_baseline_tbl.tbl`, 20 chars, hit).
* `IDS_LOAD_BASELINE_CC` - reloads the baseline from the table buffer.

You can also dump/load `IDS.BaselineTbl` with the standard cFE TBL commands
directly if you want a different destination filename.

## Configuration

Refer to
[fsw/cfs/platform_inc/ids_platform_cfg.h](fsw/cfs/platform_inc/ids_platform_cfg.h)
for default pipe depth, timing, and detector sensitivities, and to
[fsw/cfs/src/ids_msg.h](fsw/cfs/src/ids_msg.h) for the full command and
telemetry definitions.

## Releases

We use [SemVer](http://semver.org/) for versioning.
* v1.0.0 - initial release.
