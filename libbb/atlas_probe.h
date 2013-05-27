/*
 * Copyright (c) 2013 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 */

/* What's the best place for this? AA may be atlas_probe.h */
#define ATLAS_HOME      "/home/atlas"
#define ATLAS_CRONS             ATLAS_HOME "/crons"
#define ATLAS_STATUS            ATLAS_HOME "/status"
#define ATLAS_DATA_OUT          ATLAS_HOME "/data/out"
#define ATLAS_DATA_OOQ_OUT      ATLAS_HOME "/data/ooq.out"
#define ATLAS_DATA_NEW          ATLAS_HOME "/data/new"
#define ATLAS_TIMESYNC_FILE     ATLAS_STATUS "/timesync.vol"

int get_probe_id(void);
