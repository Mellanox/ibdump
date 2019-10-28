/*                  - Mellanox Confidential and Proprietary -
 *
 *  Copyright (C) Aug 2010, Mellanox Technologies Ltd.  ALL RIGHTS RESERVED.
 *
 *  Except as specifically permitted herein, no portion of the information,
 *  including but not limited to object code and source code, may be reproduced,
 *  modified, distributed, republished or otherwise exploited in any form or by
 *  any means#include <windows.h>
 for any purpose without the prior written permission of Mellanox
 *  Technologies Ltd. Use of software subject to the terms and conditions
 *  detailed in the file "LICENSE.txt".
 *
 *  End of legal section ......................................................
 */

#ifndef IBD_IBAL_ACCESS
#define IBD_IBAL_ACCESS

int ibd_ibal_open_sniffer(u_int64_t node_guid,
                          int       ib_port,
                          u_int32_t qp_num,
                          int       tx,
                          int       rx,
                          void**    context);

int ibd_ibal_close_sniffer(void* context);
#endif
