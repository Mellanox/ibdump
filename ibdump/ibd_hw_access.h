/*                  - Mellanox Confidential and Proprietary -
 *
 *  Copyright (C) Aug 2010, Mellanox Technologies Ltd.  ALL RIGHTS RESERVED.
 *
 *  Except as specifically permitted herein, no portion of the information,
 *  including but not limited to object code and source code, may be reproduced,
 *  modified, distributed, republished or otherwise exploited in any form or by
 *  any means for any purpose without the prior written permission of Mellanox
 *  Technologies Ltd. Use of software subject to the terms and conditions
 *  detailed in the file "LICENSE.txt".
 *
 *  End of legal section ......................................................
 */

#ifndef IBD_HW_ACCESS
#define IBD_HW_ACCESS

int ibd_set_hw_sniffer_mode(mfile*    mf,
                            u_int32_t devid,
                            int       ib_port,
                            u_int32_t qp_num,
                            u_int32_t mode,
                            int       tx,
                            int       rx,
                            u_int32_t source_qps[],
                            int       source_qps_num);

#endif

