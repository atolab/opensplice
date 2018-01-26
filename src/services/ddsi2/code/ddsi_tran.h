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
#ifndef _DDSI_TRAN_H_
#define _DDSI_TRAN_H_

/* DDSI Transport module */

#include "q_globals.h"
#include "q_protocol.h"

#ifdef OSPL_BUILD_DDSI2
#define OS_API OS_API_EXPORT
#else
#define OS_API OS_API_IMPORT
#endif

/* Types supporting handles */

#define DDSI_TRAN_CONN 1
#define DDSI_TRAN_LISTENER 2

/* Flags */

#define DDSI_TRAN_ON_CONNECT 0x0001

/* Core types */

typedef struct ddsi_tran_base * ddsi_tran_base_t;
typedef struct ddsi_tran_conn * ddsi_tran_conn_t;
typedef struct ddsi_tran_listener * ddsi_tran_listener_t;
typedef struct ddsi_tran_factory * ddsi_tran_factory_t;
typedef struct ddsi_tran_qos * ddsi_tran_qos_t;

/* Function pointer types */

typedef os_ssize_t (*ddsi_tran_read_fn_t) (ddsi_tran_conn_t, unsigned char *, os_size_t, nn_locator_t *);
typedef os_ssize_t (*ddsi_tran_write_fn_t) (ddsi_tran_conn_t, const nn_locator_t *, size_t, const ddsi_iovec_t *, os_uint32);
typedef int (*ddsi_tran_locator_fn_t) (ddsi_tran_base_t, nn_locator_t *);
typedef c_bool (*ddsi_tran_supports_fn_t) (os_int32);
typedef os_handle (*ddsi_tran_handle_fn_t) (ddsi_tran_base_t);
typedef int (*ddsi_tran_listen_fn_t) (ddsi_tran_listener_t);
typedef void (*ddsi_tran_free_fn_t) (void);
typedef void (*ddsi_tran_peer_locator_fn_t) (ddsi_tran_conn_t, nn_locator_t *);
typedef ddsi_tran_conn_t (*ddsi_tran_accept_fn_t) (ddsi_tran_listener_t);
typedef ddsi_tran_conn_t (*ddsi_tran_create_conn_fn_t) (os_uint32 , ddsi_tran_qos_t);
typedef ddsi_tran_listener_t (*ddsi_tran_create_listener_fn_t) (int port, ddsi_tran_qos_t);
typedef void (*ddsi_tran_release_conn_fn_t) (ddsi_tran_conn_t);
typedef void (*ddsi_tran_close_conn_fn_t) (ddsi_tran_conn_t);
typedef void (*ddsi_tran_unblock_listener_fn_t) (ddsi_tran_listener_t);
typedef void (*ddsi_tran_release_listener_fn_t) (ddsi_tran_listener_t);
typedef int (*ddsi_tran_join_mc_fn_t) (ddsi_tran_conn_t, const nn_locator_t *srcip, const nn_locator_t *mcip, const struct nn_interface *interf);
typedef int (*ddsi_tran_leave_mc_fn_t) (ddsi_tran_conn_t, const nn_locator_t *srcip, const nn_locator_t *mcip, const struct nn_interface *interf);
typedef int (*ddsi_is_mcaddr_fn_t) (ddsi_tran_factory_t tran, const nn_locator_t *loc);

enum ddsi_nearby_address_result {
  DNAR_DISTANT,
  DNAR_LOCAL,
  DNAR_SAME
};

typedef enum ddsi_nearby_address_result (*ddsi_is_nearby_address_fn_t) (ddsi_tran_factory_t tran, const nn_locator_t *loc, size_t ninterf, const struct nn_interface interf[]);

enum ddsi_locator_from_string_result {
  AFSR_OK,      /* conversion succeeded */
  AFSR_INVALID, /* bogus input */
  AFSR_UNKNOWN, /* transport or hostname lookup failure */
  AFSR_MISMATCH /* recognised format, but mismatch with expected (e.g., IPv4/IPv6) */
};

typedef enum ddsi_locator_from_string_result (*ddsi_locator_from_string_fn_t) (ddsi_tran_factory_t tran, nn_locator_t *loc, const char *str);

typedef char * (*ddsi_locator_to_string_fn_t) (ddsi_tran_factory_t tran, char *dst, size_t sizeof_dst, const nn_locator_t *loc, int with_port);

typedef int (*ddsi_enumerate_interfaces_fn_t) (ddsi_tran_factory_t tran, int max, struct os_ifAttributes_s *interfs);

/* Data types */

struct ddsi_tran_base
{
  /* Data */

  os_uint32 m_port;
  os_uint32 m_trantype;
  c_bool m_multicast;

  /* Functions */

  ddsi_tran_locator_fn_t m_locator_fn;
  ddsi_tran_handle_fn_t m_handle_fn;
};

struct ddsi_tran_conn
{
  struct ddsi_tran_base m_base;

  /* Functions */

  ddsi_tran_read_fn_t m_read_fn;
  ddsi_tran_write_fn_t m_write_fn;
  ddsi_tran_peer_locator_fn_t m_peer_locator_fn;

  /* Data */

  c_bool m_server;
  c_bool m_connless;
  c_bool m_stream;
  c_bool m_closed;
  pa_uint32_t m_count;

  /* Relationships */

  ddsi_tran_factory_t m_factory;
  ddsi_tran_listener_t m_listener;
  ddsi_tran_conn_t m_conn;
};

struct ddsi_tran_listener
{
  struct ddsi_tran_base m_base;

  /* Functions */

  ddsi_tran_listen_fn_t m_listen_fn;
  ddsi_tran_accept_fn_t m_accept_fn;

  /* Relationships */

  ddsi_tran_conn_t m_connections;
  ddsi_tran_factory_t m_factory;
  ddsi_tran_listener_t m_listener;
};

struct ddsi_tran_factory
{
  /* Functions */

  ddsi_tran_create_conn_fn_t m_create_conn_fn;
  ddsi_tran_create_listener_fn_t m_create_listener_fn;
  ddsi_tran_release_conn_fn_t m_release_conn_fn;
  ddsi_tran_close_conn_fn_t m_close_conn_fn;
  ddsi_tran_unblock_listener_fn_t m_unblock_listener_fn;
  ddsi_tran_release_listener_fn_t m_release_listener_fn;
  ddsi_tran_supports_fn_t m_supports_fn;
  ddsi_tran_free_fn_t m_free_fn;
  ddsi_tran_join_mc_fn_t m_join_mc_fn;
  ddsi_tran_leave_mc_fn_t m_leave_mc_fn;
  ddsi_is_mcaddr_fn_t m_is_mcaddr_fn;
  ddsi_is_nearby_address_fn_t m_is_nearby_address_fn;
  ddsi_locator_from_string_fn_t m_locator_from_string_fn;
  ddsi_locator_to_string_fn_t m_locator_to_string_fn;
  ddsi_enumerate_interfaces_fn_t m_enumerate_interfaces_fn;

  /* Data */

  os_int32 m_kind;
  const char * m_typename;
  const char * m_default_spdp_address;
  c_bool m_connless;
  c_bool m_stream;

  /* Relationships */

  ddsi_tran_factory_t m_factory;
};

struct ddsi_tran_qos
{
  /* QoS Data */

  c_bool m_multicast;
  int m_diffserv;
};

/* Functions and pseudo functions (macro wrappers) */

void ddsi_factory_conn_init (ddsi_tran_factory_t, ddsi_tran_conn_t);

#define ddsi_tran_type(b) (((ddsi_tran_base_t) (b))->m_trantype)
#define ddsi_tran_port(b) (((ddsi_tran_base_t) (b))->m_port)
int ddsi_tran_locator (ddsi_tran_base_t base, nn_locator_t * loc);
void ddsi_tran_free (ddsi_tran_base_t base);
void ddsi_tran_free_qos (ddsi_tran_qos_t qos);
ddsi_tran_qos_t ddsi_tran_create_qos (void);
os_handle ddsi_tran_handle (ddsi_tran_base_t base);

#define ddsi_factory_create_listener(f,p,q) (((f)->m_create_listener_fn) ((p), (q)))
#define ddsi_factory_supports(f,k) (((f)->m_supports_fn) (k))

ddsi_tran_conn_t ddsi_factory_create_conn
(
  ddsi_tran_factory_t factory,
  os_uint32 port,
  ddsi_tran_qos_t qos
);
void ddsi_factory_add (ddsi_tran_factory_t factory);
void ddsi_factory_free (ddsi_tran_factory_t factory);
ddsi_tran_factory_t ddsi_factory_find (const char * type);
ddsi_tran_factory_t ddsi_factory_find_supported_kind (os_int32 kind);
void ddsi_factory_conn_init (ddsi_tran_factory_t factory, ddsi_tran_conn_t conn);

#define ddsi_conn_handle(c) (ddsi_tran_handle (&(c)->m_base))
#define ddsi_conn_locator(c,l) (ddsi_tran_locator (&(c)->m_base,(l)))
OS_API os_ssize_t ddsi_conn_write (ddsi_tran_conn_t conn, const nn_locator_t *dst, size_t niov, const ddsi_iovec_t *iov, os_uint32 flags);
os_ssize_t ddsi_conn_read (ddsi_tran_conn_t conn, unsigned char * buf, os_size_t len, nn_locator_t *srcloc);
c_bool ddsi_conn_peer_locator (ddsi_tran_conn_t conn, nn_locator_t * loc);
void ddsi_conn_add_ref (ddsi_tran_conn_t conn);
void ddsi_conn_free (ddsi_tran_conn_t conn);

int ddsi_conn_join_mc (ddsi_tran_conn_t conn, const nn_locator_t *srcip, const nn_locator_t *mcip, const struct nn_interface *interf);
int ddsi_conn_leave_mc (ddsi_tran_conn_t conn, const nn_locator_t *srcip, const nn_locator_t *mcip, const struct nn_interface *interf);

void ddsi_conn_transfer_group_membership (ddsi_tran_conn_t conn, ddsi_tran_conn_t newconn);
int ddsi_conn_rejoin_transferred_mcgroups (ddsi_tran_conn_t conn);

int ddsi_is_mcaddr (const nn_locator_t *loc);
enum ddsi_nearby_address_result ddsi_is_nearby_address (const nn_locator_t *loc, const size_t ninterf, const struct nn_interface interf[]);
enum ddsi_locator_from_string_result ddsi_locator_from_string (nn_locator_t *loc, const char *str);

/*  8 for transport/
    1 for [
   48 for IPv6 hex digits (3*16) + separators
    2 for ]:
   10 for port (DDSI loc has signed 32-bit)
    1 for terminator
   --
   70
*/
#define DDSI_LOCSTRLEN 70

char *ddsi_locator_to_string (char *dst, size_t sizeof_dst, const nn_locator_t *loc);
char *ddsi_locator_to_string_no_port (char *dst, size_t sizeof_dst, const nn_locator_t *loc);

int ddsi_enumerate_interfaces (ddsi_tran_factory_t factory, int max, struct os_ifAttributes_s *interfs);

#define ddsi_listener_locator(s,l) (ddsi_tran_locator (&(s)->m_base,(l)))
ddsi_tran_conn_t ddsi_listener_accept (ddsi_tran_listener_t listener);
int ddsi_listener_listen (ddsi_tran_listener_t listener);
void ddsi_listener_unblock (ddsi_tran_listener_t listener);
void ddsi_listener_free (ddsi_tran_listener_t listener);
#undef OS_API
#endif

/* SHA1 not available (unoffical build.) */
