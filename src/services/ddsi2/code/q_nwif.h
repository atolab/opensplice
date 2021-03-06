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
#ifndef Q_NWIF_H
#define Q_NWIF_H

#include "os_socket.h"
#include "c_base.h"
#include "q_protocol.h" /* for nn_locator_t */

#if defined (__cplusplus)
extern "C" {
#endif

#define MAX_INTERFACES 128
struct nn_interface {
  nn_locator_t loc;
  nn_locator_t netmask;
  os_uint if_index;
  unsigned mc_capable: 1;
  unsigned point_to_point: 1;
  char *name;
};

int make_socket (os_socket *socket, unsigned short port, c_bool stream, c_bool reuse);
int find_own_ip (const char *requested_address);

#if defined (__cplusplus)
}
#endif


#endif /* Q_NWIF_H */

/* SHA1 not available (unoffical build.) */
