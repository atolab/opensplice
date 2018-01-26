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
#ifndef NN_INVERSE_UINT32_SET_H
#define NN_INVERSE_UINT32_SET_H

#include "ut_avl.h"

struct inverse_uint32_set_node {
  ut_avlNode_t avlnode;
  os_uint32 min, max;
};
struct inverse_uint32_set {
  ut_avlTree_t ids;
  os_uint32 cursor;
  os_uint32 min, max;
};

void inverse_uint32_set_init(struct inverse_uint32_set *set, os_uint32 min, os_uint32 max);
void inverse_uint32_set_fini(struct inverse_uint32_set *set);
int inverse_uint32_set_alloc(os_uint32 * const id, struct inverse_uint32_set *set);
void inverse_uint32_set_free(struct inverse_uint32_set *set, os_uint32 id);

#endif
