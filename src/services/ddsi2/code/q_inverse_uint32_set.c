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
#include <assert.h>
#include <stddef.h>
#include "os_heap.h"
#include "ut_avl.h"
#include "q_config.h"
#include "q_log.h"
#include "q_inverse_uint32_set.h"

static int os_uint32_cmp(const void *va, const void *vb);

static ut_avlTreedef_t inverse_uint32_set_td = UT_AVL_TREEDEF_INITIALIZER(offsetof(struct inverse_uint32_set_node, avlnode), offsetof(struct inverse_uint32_set_node, min), os_uint32_cmp, 0);

static int os_uint32_cmp(const void *va, const void *vb)
{
  const os_uint32 *a = va;
  const os_uint32 *b = vb;
  return (*a == *b) ? 0 : (*a < *b) ? -1 : 1;
}

static void check(const struct inverse_uint32_set *set)
{
#ifndef NDEBUG
  ut_avlIter_t it;
  struct inverse_uint32_set_node *pn = NULL, *n;
  assert(set->min <= set->max);
  assert(set->cursor >= set->min);
  assert(set->cursor <= set->max);
  for (n = ut_avlIterFirst(&inverse_uint32_set_td, &set->ids, &it); n; pn = n, n = ut_avlIterNext(&it))
  {
    assert(n->min <= n->max);
    assert(n->min >= set->min);
    assert(n->max <= set->max);
    assert(pn == NULL || n->min > pn->max+1);
  }
#endif
}

void inverse_uint32_set_init(struct inverse_uint32_set *set, os_uint32 min, os_uint32 max)
{
  struct inverse_uint32_set_node *n;
  ut_avlInit(&inverse_uint32_set_td, &set->ids);
  set->cursor = min;
  set->min = min;
  set->max = max;
  n = os_malloc(sizeof(*n));
  n->min = min;
  n->max = max;
  ut_avlInsert(&inverse_uint32_set_td, &set->ids, n);
  check(set);
}

void inverse_uint32_set_fini(struct inverse_uint32_set *set)
{
  ut_avlFree(&inverse_uint32_set_td, &set->ids, os_free);
}

static os_uint32 inverse_uint32_set_alloc_use_min(struct inverse_uint32_set *set, struct inverse_uint32_set_node *n)
{
  const os_uint32 id = n->min;
  if (n->min == n->max)
  {
    ut_avlDelete(&inverse_uint32_set_td, &set->ids, n);
    os_free(n);
  }
  else
  {
    /* changing the key in-place here: the key value may be changing, but the structure of the tree is not */
    n->min++;
  }
  return id;
}

int inverse_uint32_set_alloc(os_uint32 * const id, struct inverse_uint32_set *set)
{
  struct inverse_uint32_set_node *n;
  if ((n = ut_avlLookupPredEq(&inverse_uint32_set_td, &set->ids, &set->cursor)) != NULL && set->cursor <= n->max) {
    /* n is [a,b] s.t. a <= C <= b, so C is available */
    *id = set->cursor;
    if (n->min == set->cursor)
    {
      (void)inverse_uint32_set_alloc_use_min(set, n);
    }
    else if (set->cursor == n->max)
    {
      assert(n->min < n->max);
      n->max--;
    }
    else
    {
      struct inverse_uint32_set_node *n1 = os_malloc(sizeof(*n1));
      assert(n->min < set->cursor && set->cursor < n->max);
      n1->min = set->cursor + 1;
      n1->max = n->max;
      n->max = set->cursor - 1;
      ut_avlInsert(&inverse_uint32_set_td, &set->ids, n1);
    }
  }
  else if ((n = ut_avlLookupSucc(&inverse_uint32_set_td, &set->ids, &set->cursor)) != NULL)
  {
    /* n is [a,b] s.t. a > C and all intervals [a',b'] in tree have a' <= C */
    *id = inverse_uint32_set_alloc_use_min(set, n);
  }
  else if ((n = ut_avlFindMin(&inverse_uint32_set_td, &set->ids)) != NULL)
  {
    /* no available ids >= cursor: wrap around and use the first available */
    assert(n->max < set->cursor);
    *id = inverse_uint32_set_alloc_use_min(set, n);
  }
  else
  {
    return 0;
  }
  assert(*id >= set->min);
  set->cursor = (*id < set->max) ? (*id + 1) : set->min;
  check(set);
  return 1;
}

void inverse_uint32_set_free(struct inverse_uint32_set *set, os_uint32 id)
{
  struct inverse_uint32_set_node *n;
  const os_uint32 idp1 = id + 1;
  ut_avlIPath_t ip;
  if ((n = ut_avlLookupPredEq(&inverse_uint32_set_td, &set->ids, &id)) != NULL && id <= n->max + 1) {
    if (id <= n->max)
    {
      /* n is [a,b] s.t. a <= I <= b: so it is already in the set */
      return;
    }
    else
    {
      struct inverse_uint32_set_node *n1;
      ut_avlDPath_t dp;
      /* grow the interval, possibly coalesce with next */
      if ((n1 = ut_avlLookupDPath(&inverse_uint32_set_td, &set->ids, &idp1, &dp)) == NULL) {
        n->max = id;
      } else {
        n->max = n1->max;
        ut_avlDeleteDPath(&inverse_uint32_set_td, &set->ids, n1, &dp);
        os_free(n1);
      }
    }
  }
  else if ((n = ut_avlLookupIPath(&inverse_uint32_set_td, &set->ids, &idp1, &ip)) != NULL) {
    /* changing the key in-place here: the key value may be changing, but the structure of the tree is not or the previous case would have applied */
    n->min = id;
  }
  else
  {
    /* no adjacent interval */
    n = os_malloc(sizeof(*n));
    n->min = n->max = id;
    ut_avlInsertIPath(&inverse_uint32_set_td, &set->ids, n, &ip);
  }
  check(set);
}

