/*                  - Mellanox Confidential and Proprietary -
 *
 *  Copyright (C) Jan 2010, Mellanox Technologies Ltd.  ALL RIGHTS RESERVED.
 *
 *  Except as specifically permitted herein, no portion of the information,
 *  including but not limited to object code and source code, may be reproduced,
 *  modified, distributed, republished or otherwise exploited in any form or by
 *  any means for any purpose without the prior written permission of Mellanox
 *  Technologies Ltd. Use of software subject to the terms and conditions
 *  detailed in the file "LICENSE.txt".
 *
 *  End of legal section ......................................................
 *
 *  See README in the ibdump package for functional details.
 *  Note:
 *  This code is in beta stage and may change in the future.
 *
 * $Id$
 */

/* qkey value that we will use */
#define DEF_QKEY 0x12345
/* Global Routing Header size */
#define GRH_SIZE 40

/* Sniffer formats */
#define DLT_EN10MB        1     /* Ethernet (10Mb) */
#define DLT_ERF         197     /* ERF Pseudo header */

#define PM_ENCAP_ETHERTYPE 0x1123
#define ERF_TYPE_ETH                2
#define ERF_TYPE_INFINIBAND         21
#define MAX_SRC_QPS 16

typedef u_int64_t erf_timestamp_t;

typedef struct erf_record {
    erf_timestamp_t   ts;
    u_int8_t          type;
    u_int8_t          flags;
    u_int16_t         rlen;
    u_int16_t         lctr;
    u_int16_t         wlen;
} erf_header_t;

typedef struct pcaprec_hdr_s {
    u_int32_t ts_sec;         /* timestamp seconds */
    u_int32_t ts_usec;        /* timestamp microseconds */
    u_int32_t incl_len;       /* number of octets of packet saved in file */
    u_int32_t orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

typedef struct pcap_hdr_s {
    u_int32_t magic_number;   /* magic number */
    u_int16_t version_major;  /* major version number */
    u_int16_t version_minor;  /* minor version number */
    int32_t   thiszone;       /* GMT to local correction */
    u_int32_t sigfigs;        /* accuracy of timestamps */
    u_int32_t snaplen;        /* max length of captured packets, in octets */
    u_int32_t network;        /* data link type */
} pcap_hdr_t;

typedef struct rec_hdr_s {
    pcaprec_hdr_t pcap;
    erf_header_t  erf;
} rec_hdr_t;

struct resources {
    struct ibv_device_attr  device_attr;    /* Device attributes */
    struct ibv_port_attr    port_attr;      /* IB port attributes */
    struct ibv_device       **dev_list;     /* device list */
    struct ibv_context      *ib_ctx;        /* device handle */
    struct ibv_pd           *pd;            /* PD handle */
    struct ibv_cq           *cq;            /* CQ handle */
    struct ibv_qp           *qp;            /* QP handle */
    struct ibv_ah           *ah;            /* AH handle */
    struct ibv_mr           *mr;            /* MR handle */
    char                    **buf;          /* memory buffer pointer */
    char                    *buf_alloc_ptr;
    int                     entry_size;
    FILE                    *fh;            /* pcap file handle */
#if defined(WITH_MFT) || defined(WITH_MSTFLINT)
    mfile*                  mf;             /* CR access handle */
#endif
#ifndef WIN_NOT_SUPPORTED
#ifdef UPSTREAM_KERNEL
    struct ibv_flow*        flow;
#else
    struct ibv_exp_flow*    flow;
#endif
#else
    void*                   ibal_ctx;
#endif
    char*                   mem_buf;        /* in memory mode */
    char*                   mem_buf2;       /* in multithreaded mode */

    /* status counters */
    u_int64_t               dumped_bytes;
    u_int64_t               sniffed_bytes;
    u_int64_t               sniffed_pkts;
    u_int64_t               buf_length[2];

    u_int32_t               dev_rev_id;
    int                     network_current_buf;
    char*                   thread_buf[2];
    int                     thread_status[2];
};

/* structure of test parameters */
struct config_t {
    char           *dev_name;      /* IB device name */
    char           *mst_dev_name;  /* MST device name */
    char           *out_file_name;
    int             ib_port;       /* local IB port to work with */
    u_int64_t       mem_size;
    int             decap_mode;
    u_int32_t       log2entries_num;
    u_int32_t       entries_num;
    u_int8_t        erf_type;
    char*           src_qp_str;
    u_int8_t        is_silent;
    u_int8_t        is_eth;
    u_int8_t        to_stdout;
    int             with_erf;     /* -1 : default per proto */
    u_int8_t        jumbo_mtu;
    u_int8_t        use_a0_mode;
    u_int8_t        contiguous_pages;
    u_int8_t        writer_thread;
    u_int8_t        mem_mode;
};

struct config_t config = {
    NULL,               /* dev_name */
    NULL,
    "sniffer.pcap",     /* out file name */
    1,                  /* ib_port */
    0,                  /* mem size */
    0,                  /* decap_mode */
    12,
    4096,
    ERF_TYPE_INFINIBAND, /* erf_type: InfiniBand (21)*/
    NULL,                /* src_qp_str */
    0,                   /* is_silent */
    0,
    0,
    -1,
    0,
    0,
    0,
    0,                    /* writer_thread*/
    0
};
