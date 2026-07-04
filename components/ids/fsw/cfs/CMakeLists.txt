cmake_minimum_required(VERSION 2.6.4)
project(CFS_IDS_APP C)

include(../../../ComponentSettings.cmake)

include_directories(mission_inc)
include_directories(platform_inc)
include_directories(src)

include_directories(${APPLICATION_PLATFORM_INC_LIST})

aux_source_directory(src APP_SRC_FILES)

# Create the app module
add_cfe_app(ids ${APP_SRC_FILES})

# Table source is named explicitly rather than via aux_source_directory(tables ...):
# that glob was coming back empty for this component at configure time (verified via
# build log - no "table definition" message for ids ever appeared), even though the
# file demonstrably exists on disk with correct content. Passing the path directly
# guarantees add_cfe_tables gets a non-empty file list regardless of that glob issue.
add_cfe_tables(ids tables/ids_baseline_tbl.c)

# Note: no unit-test subdirectory yet - see components/sample/fsw/cfs/unit-test
# for the pattern to follow when adding coverage for this app.
