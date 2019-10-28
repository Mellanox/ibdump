#!/usr/bin/env bash
/mswg/projects/mft/mft_build/utils/unifdef/unifdef -UMLNX_INT_NAMING -UMLNX_INT_DCT -UMLNX_INT_ROCE_V1_5 packet-infiniband-full.c > packet-infiniband.c
/mswg/projects/mft/mft_build/utils/unifdef/unifdef -UMLNX_INT_NAMING -UMLNX_INT_DCT -UMLNX_INT_ROCE_V1_5 packet-infiniband-full.h > packet-infiniband.h
