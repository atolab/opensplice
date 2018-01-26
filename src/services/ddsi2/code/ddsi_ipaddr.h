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
#ifndef DDSI_IPADDR_H
#define DDSI_IPADDR_H

#include "ddsi_tran.h"

enum ddsi_nearby_address_result ddsi_ipaddr_is_nearby_address (ddsi_tran_factory_t tran, const nn_locator_t *loc, const size_t ninterf, const struct nn_interface interf[]);
enum ddsi_locator_from_string_result ddsi_ipaddr_from_string (ddsi_tran_factory_t tran, nn_locator_t *loc, const char *str, os_int32 kind);
char *ddsi_ipaddr_to_string (ddsi_tran_factory_t tran, char *dst, size_t sizeof_dst, const nn_locator_t *loc, int with_port);
void ddsi_ipaddr_to_loc (nn_locator_t *dst, const os_sockaddr_storage *src, os_int32 kind);
void ddsi_ipaddr_from_loc (os_sockaddr_storage *dst, const nn_locator_t *src);

#endif
