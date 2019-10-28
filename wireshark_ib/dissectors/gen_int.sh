#!/usr/bin/env bash
/mswg/projects/mft/mft_build/utils/unifdef/unifdef -b -DMLNX_INT_NAMING -DMLNX_INT_DCT -DMLNX_INT_ROCE_V1_5 packet-infiniband-full.c > packet-infiniband.c
/mswg/projects/mft/mft_build/utils/unifdef/unifdef -b -DMLNX_INT_NAMING -DMLNX_INT_DCT -DMLNX_INT_ROCE_V1_5 packet-infiniband-full.h > packet-infiniband.h
