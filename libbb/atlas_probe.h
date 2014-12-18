/*
 * Copyright (c) 2013 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 */

#define ATLAS_HOME      "/home/atlas"
#define ATLAS_STATUS            ATLAS_HOME "/status"
#define ATLAS_TIMESYNC_FILE     ATLAS_STATUS "/timesync.vol"

#define ATLAS_CRONS             CONFIG_FEATURE_EPERD_CRONS_DIR
#define ATLAS_DATA_OUT          CONFIG_FEATURE_EPERD_OUT_DIR
#define ATLAS_DATA_NEW          CONFIG_FEATURE_EPERD_NEW_DIR
#define ATLAS_DATA_OOQ_OUT      CONFIG_FEATURE_EPERD_NEW_DIR
#define OOQD_NEW_PREFIX		CONFIG_FEATURE_EOOQD_PREFIX
#define OOQD_OUT_PREFIX		CONFIG_FEATURE_EOOQD_OUT_DIR

int get_probe_id(void);
