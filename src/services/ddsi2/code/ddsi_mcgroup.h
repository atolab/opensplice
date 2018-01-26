/*
 *                         OpenSplice DDS
 *
 *   This software and documentation are Copyright 2006 to TO_YEAR PrismTech
 *   Limited, its affiliated companies and licensors. All rights reserved.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 *
 */
#ifndef DDSI_MCGROUP_H
#define DDSI_MCGROUP_H

#include "ddsi_tran.h"

struct nn_group_membership;

struct nn_group_membership *new_group_membership (void);
void free_group_membership (struct nn_group_membership *mship);
int ddsi_join_mc (ddsi_tran_conn_t conn, const nn_locator_t *srcip, const nn_locator_t *mcip);
int ddsi_leave_mc (ddsi_tran_conn_t conn, const nn_locator_t *srcip, const nn_locator_t *mcip);
void ddsi_transfer_group_membership (ddsi_tran_conn_t conn, ddsi_tran_conn_t newconn);
int ddsi_rejoin_transferred_mcgroups (ddsi_tran_conn_t conn);

#endif
