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
#include <ctype.h>
#include "os_heap.h"
#include "os_atomics.h"
#include "ddsi_tran.h"
#include "q_config.h"
#include "q_log.h"

static ddsi_tran_factory_t ddsi_tran_factories = NULL;

void ddsi_factory_add (ddsi_tran_factory_t factory)
{
  factory->m_factory = ddsi_tran_factories;
  ddsi_tran_factories = factory;
}

ddsi_tran_factory_t ddsi_factory_find (const char * type)
{
  /* FIXME: should speed up */
  ddsi_tran_factory_t factory = ddsi_tran_factories;

  while (factory)
  {
    if (strcmp (factory->m_typename, type) == 0)
    {
      break;
    }
    factory = factory->m_factory;
  }

  return factory;
}

static ddsi_tran_factory_t ddsi_factory_find_with_len (const char * type, size_t len)
{
  /* FIXME: should speed up */
  ddsi_tran_factory_t factory = ddsi_tran_factories;

  while (factory)
  {
    if (strncmp (factory->m_typename, type, len) == 0 && factory->m_typename[len] == 0)
    {
      break;
    }
    factory = factory->m_factory;
  }

  return factory;
}

ddsi_tran_factory_t ddsi_factory_find_supported_kind (os_int32 kind)
{
  /* FIXME: MUST speed up */
  ddsi_tran_factory_t factory;
  for (factory = ddsi_tran_factories; factory; factory = factory->m_factory) {
    if (factory->m_supports_fn(kind)) {
      return factory;
    }
  }
  return NULL;
}

void ddsi_factory_free (ddsi_tran_factory_t factory)
{
  if (factory && factory->m_free_fn)
  {
    (factory->m_free_fn) ();
  }
}

void ddsi_conn_free (ddsi_tran_conn_t conn)
{
  if (conn)
  {
    if (! conn->m_closed)
    {
      conn->m_closed = TRUE;
      if (conn->m_factory->m_close_conn_fn)
      {
        (conn->m_factory->m_close_conn_fn) (conn);
      }
    }
    if (pa_dec32_nv (&conn->m_count) == 0)
    {
      (conn->m_factory->m_release_conn_fn) (conn);
    }
  }
}

void ddsi_conn_add_ref (ddsi_tran_conn_t conn)
{
  pa_inc32 (&conn->m_count);
}

void ddsi_factory_conn_init (ddsi_tran_factory_t factory, ddsi_tran_conn_t conn)
{
  pa_st32 (&conn->m_count, 1);
  conn->m_connless = factory->m_connless;
  conn->m_stream = factory->m_stream;
  conn->m_factory = factory;
}

os_ssize_t ddsi_conn_read (ddsi_tran_conn_t conn, unsigned char * buf, os_size_t len, nn_locator_t *srcloc)
{
  return (conn->m_closed) ? -1 : (conn->m_read_fn) (conn, buf, len, srcloc);
}

os_ssize_t ddsi_conn_write (ddsi_tran_conn_t conn, const nn_locator_t *dst, size_t niov, const ddsi_iovec_t *iov, os_uint32 flags)
{
  os_ssize_t ret = -1;
  if (! conn->m_closed)
  {
    ret = (conn->m_write_fn) (conn, dst, niov, iov, flags);
  }

  /* Check that write function is atomic (all or nothing) */
#ifndef NDEBUG
  {
    size_t i, len;
    for (i = 0, len = 0; i < niov; i++) {
      len += iov[i].iov_len;
    }
    assert (ret == -1 || (os_size_t) ret == len);
  }
#endif
  return ret;
}

c_bool ddsi_conn_peer_locator (ddsi_tran_conn_t conn, nn_locator_t * loc)
{
  if (conn->m_peer_locator_fn)
  {
    (conn->m_peer_locator_fn) (conn, loc);
    return TRUE;
  }
  return FALSE;
}

void ddsi_tran_free_qos (ddsi_tran_qos_t qos)
{
  os_free (qos);
}

int ddsi_conn_join_mc (ddsi_tran_conn_t conn, const nn_locator_t *srcloc, const nn_locator_t *mcloc, const struct nn_interface *interf)
{
  return conn->m_factory->m_join_mc_fn (conn, srcloc, mcloc, interf);
}

int ddsi_conn_leave_mc (ddsi_tran_conn_t conn, const nn_locator_t *srcloc, const nn_locator_t *mcloc, const struct nn_interface *interf)
{
  return conn->m_factory->m_leave_mc_fn (conn, srcloc, mcloc, interf);
}

os_handle ddsi_tran_handle (ddsi_tran_base_t base)
{
  return (base->m_handle_fn) (base);
}

ddsi_tran_qos_t ddsi_tran_create_qos (void)
{
  ddsi_tran_qos_t qos;
  qos = (ddsi_tran_qos_t) os_malloc (sizeof (*qos));
  memset (qos, 0, sizeof (*qos));
  return qos;
}

ddsi_tran_conn_t ddsi_factory_create_conn
(
  ddsi_tran_factory_t factory,
  os_uint32 port,
  ddsi_tran_qos_t qos
)
{
  return factory->m_create_conn_fn (port, qos);
}

int ddsi_tran_locator (ddsi_tran_base_t base, nn_locator_t * loc)
{
  return (base->m_locator_fn) (base, loc);
}

int ddsi_listener_listen (ddsi_tran_listener_t listener)
{
  return (listener->m_listen_fn) (listener);
}

ddsi_tran_conn_t ddsi_listener_accept (ddsi_tran_listener_t listener)
{
  return (listener->m_accept_fn) (listener);
}

void ddsi_tran_free (ddsi_tran_base_t base)
{
  if (base)
  {
    if (base->m_trantype == DDSI_TRAN_CONN)
    {
      ddsi_conn_free ((ddsi_tran_conn_t) base);
    }
    else
    {
      ddsi_listener_unblock ((ddsi_tran_listener_t) base);
      ddsi_listener_free ((ddsi_tran_listener_t) base);
    }
  }
}

void ddsi_listener_unblock (ddsi_tran_listener_t listener)
{
  if (listener)
  {
    (listener->m_factory->m_unblock_listener_fn) (listener);
  }
}

void ddsi_listener_free (ddsi_tran_listener_t listener)
{
  if (listener)
  {
    (listener->m_factory->m_release_listener_fn) (listener);
  }
}

int ddsi_is_mcaddr (const nn_locator_t *loc)
{
  /* FIXME: should set m_is_mcaddr_fn to a function returning false if transport doesn't provide an implementation, and get rid of the test */
  /* FIXME: shouldn't I look up the transport from the locator kind? I think so */
  ddsi_tran_factory_t tran = ddsi_factory_find_supported_kind(loc->kind);
  return tran->m_is_mcaddr_fn ? tran->m_is_mcaddr_fn (tran, loc) : 0;
}

enum ddsi_nearby_address_result ddsi_is_nearby_address (const nn_locator_t *loc, size_t ninterf, const struct nn_interface interf[])
{
  ddsi_tran_factory_t tran = ddsi_factory_find_supported_kind(loc->kind);
  return tran->m_is_nearby_address_fn ? tran->m_is_nearby_address_fn (tran, loc, ninterf, interf) : DNAR_DISTANT;
}

enum ddsi_locator_from_string_result ddsi_locator_from_string (nn_locator_t *loc, const char *str)
{
  const char *sep = strchr(str, '/');
  ddsi_tran_factory_t tran;
  if (sep == str) {
    return AFSR_INVALID;
  } else if (sep > str) {
    const char *cur = sep;
    while (cur-- > str)
      if (!isalnum((unsigned char)*cur) && *cur != '_')
        return AFSR_INVALID;
    tran = ddsi_factory_find_with_len(str, (size_t)(sep - str));
    if (tran == NULL)
      return AFSR_UNKNOWN;
  } else {
    /* FIXME: am I happy with defaulting it like this? */
    tran = gv.m_factory;
  }
  return tran->m_locator_from_string_fn (tran, loc, sep ? sep + 1 : str);
}

char *ddsi_locator_to_string (char *dst, size_t sizeof_dst, const nn_locator_t *loc)
{
  /* FIXME: should add a "factory" for INVALID locators */
  if (loc->kind != NN_LOCATOR_KIND_INVALID) {
    ddsi_tran_factory_t tran = ddsi_factory_find_supported_kind(loc->kind);
    int pos = snprintf (dst, sizeof_dst, "%s/", tran->m_typename);
    if (0 < pos && (size_t)pos < sizeof_dst)
      (void) tran->m_locator_to_string_fn (tran, dst + (size_t)pos, sizeof_dst - (size_t)pos, loc, 1);
  } else {
    snprintf (dst, sizeof_dst, "invalid/0:0");
  }
  return dst;
}

char *ddsi_locator_to_string_no_port (char *dst, size_t sizeof_dst, const nn_locator_t *loc)
{
  if (loc->kind != NN_LOCATOR_KIND_INVALID) {
    ddsi_tran_factory_t tran = ddsi_factory_find_supported_kind(loc->kind);
    int pos = snprintf (dst, sizeof_dst, "%s/", tran->m_typename);
    if (0 < pos && (size_t)pos < sizeof_dst)
      (void) tran->m_locator_to_string_fn (tran, dst + (size_t)pos, sizeof_dst - (size_t)pos, loc, 0);
  } else {
    snprintf (dst, sizeof_dst, "invalid/0");
  }
  return dst;
}

int ddsi_enumerate_interfaces (ddsi_tran_factory_t factory, int max, struct os_ifAttributes_s *interfs)
{
  /* FIXME: HACK */
  if (factory->m_enumerate_interfaces_fn == 0)
    return 0;
  return factory->m_enumerate_interfaces_fn (factory, max, interfs);
}

/* SHA1 not available (unoffical build.) */
