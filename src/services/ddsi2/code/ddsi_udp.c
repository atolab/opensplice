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
#include "os_heap.h"
#include "os_atomics.h"
#include "ddsi_tran.h"
#include "ddsi_udp.h"
#include "ddsi_ipaddr.h"
#include "ddsi_mcgroup.h"
#include "q_nwif.h"
#include "q_config.h"
#include "q_log.h"
#include "q_pcap.h"
#include "os_errno.h"

extern void ddsi_factory_conn_init (ddsi_tran_factory_t factory, ddsi_tran_conn_t conn);

typedef struct ddsi_tran_factory * ddsi_udp_factory_t;

typedef struct ddsi_udp_config
{
  struct nn_group_membership *mship;
}
* ddsi_udp_config_t;

typedef struct ddsi_udp_conn
{
  struct ddsi_tran_conn m_base;
  os_socket m_sock;
#if defined _WIN32 && !defined WINCE
  WSAEVENT m_sockEvent;
#endif
  int m_diffserv;
}
* ddsi_udp_conn_t;

static struct ddsi_udp_config ddsi_udp_config_g;
static struct ddsi_tran_factory ddsi_udp_factory_g;
static pa_uint32_t init_g = PA_UINT32_INIT(0);

static os_ssize_t ddsi_udp_conn_read (ddsi_tran_conn_t conn, unsigned char * buf, os_size_t len, nn_locator_t *srcloc)
{
  int err;
  os_ssize_t ret;
  struct msghdr msghdr;
  os_sockaddr_storage src;
  struct iovec msg_iov;
  socklen_t srclen = (socklen_t) sizeof (src);

  msg_iov.iov_base = (void*) buf;
  msg_iov.iov_len = len;

  memset (&msghdr, 0, sizeof (msghdr));

  msghdr.msg_name = &src;
  msghdr.msg_namelen = srclen;
  msghdr.msg_iov = &msg_iov;
  msghdr.msg_iovlen = 1;

  do {
    ret = recvmsg(((ddsi_udp_conn_t) conn)->m_sock, &msghdr, 0);
    err = (ret == -1) ? os_getErrno() : 0;
  } while (err == os_sockEINTR);

  if (ret > 0)
  {
    if (srcloc)
      ddsi_ipaddr_to_loc(srcloc, &src, src.ss_family == AF_INET ? NN_LOCATOR_KIND_UDPv4 : NN_LOCATOR_KIND_UDPv6);

    /* Check for udp packet truncation */
    if ((((os_size_t) ret) > len)
#if SYSDEPS_MSGHDR_FLAGS
        || (msghdr.msg_flags & MSG_TRUNC)
#endif
        )
    {
      char addrbuf[DDSI_LOCSTRLEN];
      nn_locator_t tmp;
      ddsi_ipaddr_to_loc(&tmp, &src, src.ss_family == AF_INET ? NN_LOCATOR_KIND_UDPv4 : NN_LOCATOR_KIND_UDPv6);
      ddsi_locator_to_string(addrbuf, sizeof(addrbuf), &tmp);
      NN_WARNING3 ("%s => %d truncated to %d\n", addrbuf, (int)ret, (int)len);
    }
  }
  else if (err != os_sockENOTSOCK && err != os_sockECONNRESET)
  {
    NN_ERROR3 ("UDP recvmsg sock %d: ret %d errno %d\n", (int) ((ddsi_udp_conn_t) conn)->m_sock, (int) ret, err);
  }
  return ret;
}

/* Turns out Darwin uses "int" for msg_iovlen, but glibc uses "size_t". The simplest
 way out is to do the assignment with the conversion warnings disabled */
OSPL_DIAG_OFF(conversion)
static void set_msghdr_iov (struct msghdr *mhdr, ddsi_iovec_t *iov, size_t iovlen)
{
  mhdr->msg_iov = iov;
  mhdr->msg_iovlen = iovlen;
}
OSPL_DIAG_ON(conversion)

static os_ssize_t ddsi_udp_conn_write (ddsi_tran_conn_t conn, const nn_locator_t *dst, size_t niov, const ddsi_iovec_t *iov, os_uint32 flags)
{
  int err;
  os_ssize_t ret;
  unsigned retry = 2;
  int sendflags = 0;
  struct msghdr msg;
  os_sockaddr_storage dstaddr;
  assert(niov <= INT_MAX);
  ddsi_ipaddr_from_loc(&dstaddr, dst);
  memset(&msg, 0, sizeof(msg));
  set_msghdr_iov (&msg, (ddsi_iovec_t *) iov, niov);
  msg.msg_name = &dstaddr;
  msg.msg_namelen = (socklen_t) os_sockaddrSizeof((os_sockaddr *) &dstaddr);
  msg.msg_flags = (int) flags;
#ifdef MSG_NOSIGNAL
  sendflags |= MSG_NOSIGNAL;
#endif
  do {
    ddsi_udp_conn_t uc = (ddsi_udp_conn_t) conn;
    ret = sendmsg (uc->m_sock, &msg, sendflags);
    err = (ret == -1) ? os_getErrno() : 0;
#if defined _WIN32 && !defined WINCE
    if (err == os_sockEWOULDBLOCK) {
      WSANETWORKEVENTS ev;
      WaitForSingleObject(uc->m_sockEvent, INFINITE);
      WSAEnumNetworkEvents(uc->m_sock, uc->m_sockEvent, &ev);
    }
#endif
  } while (err == os_sockEINTR || err == os_sockEWOULDBLOCK || (err == os_sockEPERM && retry-- > 0));
  if (ret > 0 && gv.pcap_fp)
  {
    os_sockaddr_storage sa;
    socklen_t alen = sizeof (sa);
    if (getsockname (((ddsi_udp_conn_t) conn)->m_sock, (struct sockaddr *) &sa, &alen) == -1)
      memset(&sa, 0, sizeof(sa));
    write_pcap_sent (gv.pcap_fp, now (), &sa, &msg, (os_size_t) ret);
  }
  else if (ret == -1)
  {
    switch (err)
    {
      case os_sockEINTR:
      case os_sockEPERM:
      case os_sockECONNRESET:
#ifdef os_sockENETUNREACH
      case os_sockENETUNREACH:
#endif
#ifdef os_sockEHOSTUNREACH
      case os_sockEHOSTUNREACH:
#endif
        break;
      default:
        NN_ERROR1("ddsi_udp_conn_write failed with error code %d", err);
    }
  }
  return ret;
}

static os_handle ddsi_udp_conn_handle (ddsi_tran_base_t base)
{
  return ((ddsi_udp_conn_t) base)->m_sock;
}

static c_bool ddsi_udp_supports (os_int32 kind)
{
  return
  (
    (config.transport_selector == TRANS_UDP && kind == NN_LOCATOR_KIND_UDPv4)
#if OS_SOCKET_HAS_IPV6
    || (config.transport_selector == TRANS_UDP6 && kind == NN_LOCATOR_KIND_UDPv6)
#endif
  );
}

static int ddsi_udp_conn_locator (ddsi_tran_base_t base, nn_locator_t *loc)
{
  int ret = -1;
  ddsi_udp_conn_t uc = (ddsi_udp_conn_t) base;
  if (uc->m_sock != Q_INVALID_SOCKET)
  {
    loc->kind = ddsi_udp_factory_g.m_kind;
    loc->port = uc->m_base.m_base.m_port;
    memcpy(loc->address, gv.extloc.address, sizeof (loc->address));
    ret = 0;
  }
  return ret;
}

static unsigned short sockaddr_get_port (const os_sockaddr_storage *addr)
{
  if (addr->ss_family == AF_INET)
    return ntohs (((os_sockaddr_in *) addr)->sin_port);
#if OS_SOCKET_HAS_IPV6
  else
    return ntohs (((os_sockaddr_in6 *) addr)->sin6_port);
#endif
}

static unsigned short get_socket_port (os_socket socket)
{
  os_sockaddr_storage addr;
  socklen_t addrlen = sizeof (addr);
  if (getsockname (socket, (os_sockaddr *) &addr, &addrlen) < 0)
  {
    int err = os_getErrno();
    NN_ERROR1 ("ddsi_udp_get_socket_port: getsockname errno %d\n", err);
    return 0;
  }
  return sockaddr_get_port(&addr);
}

static ddsi_tran_conn_t ddsi_udp_create_conn
(
  os_uint32 port,
  ddsi_tran_qos_t qos
)
{
  int ret;
  os_socket sock;
  ddsi_udp_conn_t uc = NULL;
  c_bool mcast = (c_bool) (qos ? qos->m_multicast : FALSE);

  /* If port is zero, need to create dynamic port */

  ret = make_socket
  (
    &sock,
    (unsigned short) port,
    FALSE,
    mcast
  );

  if (ret == 0)
  {
    uc = (ddsi_udp_conn_t) os_malloc (sizeof (*uc));
    memset (uc, 0, sizeof (*uc));

    uc->m_sock = sock;
    uc->m_diffserv = qos ? qos->m_diffserv : 0;
#if defined _WIN32 && !defined WINCE
    uc->m_sockEvent = WSACreateEvent();
    WSAEventSelect(uc->m_sock, uc->m_sockEvent, FD_WRITE);
#endif

    ddsi_factory_conn_init (&ddsi_udp_factory_g, &uc->m_base);
    uc->m_base.m_base.m_port = get_socket_port (sock);
    uc->m_base.m_base.m_trantype = DDSI_TRAN_CONN;
    uc->m_base.m_base.m_multicast = mcast;
    uc->m_base.m_base.m_handle_fn = ddsi_udp_conn_handle;
    uc->m_base.m_base.m_locator_fn = ddsi_udp_conn_locator;

    uc->m_base.m_read_fn = ddsi_udp_conn_read;
    uc->m_base.m_write_fn = ddsi_udp_conn_write;

    nn_log
    (
      LC_INFO,
      "ddsi_udp_create_conn %s socket %d port %d\n",
      mcast ? "multicast" : "unicast",
      uc->m_sock,
      uc->m_base.m_base.m_port
    );
  }
  else
  {
    if (config.participantIndex != PARTICIPANT_INDEX_AUTO)
    {
      NN_ERROR2
      (
        "UDP make_socket failed for %s port %d\n",
        mcast ? "multicast" : "unicast",
        port
      );
    }
  }

  return uc ? &uc->m_base : NULL;
}

static int joinleave_asm_mcgroup (os_socket socket, int join, const nn_locator_t *mcloc, const struct nn_interface *interf)
{
  int rc;
  os_sockaddr_storage mcip;
  ddsi_ipaddr_from_loc(&mcip, mcloc);
#if OS_SOCKET_HAS_IPV6
  if (config.transport_selector == TRANS_UDP6)
  {
    os_ipv6_mreq ipv6mreq;
    memset (&ipv6mreq, 0, sizeof (ipv6mreq));
    memcpy (&ipv6mreq.ipv6mr_multiaddr, &((os_sockaddr_in6 *) &mcloc)->sin6_addr, sizeof (ipv6mreq.ipv6mr_multiaddr));
    ipv6mreq.ipv6mr_interface = interf ? interf->if_index : 0;
    rc = os_sockSetsockopt (socket, IPPROTO_IPV6, join ? IPV6_JOIN_GROUP : IPV6_LEAVE_GROUP, &ipv6mreq, sizeof (ipv6mreq));
  }
  else
#endif
  {
    struct ip_mreq mreq;
    mreq.imr_multiaddr = ((os_sockaddr_in *) &mcip)->sin_addr;
    if (interf)
      memcpy (&mreq.imr_interface, interf->loc.address + 12, sizeof (mreq.imr_interface));
    else
      mreq.imr_interface.s_addr = htonl (INADDR_ANY);
    rc = os_sockSetsockopt (socket, IPPROTO_IP, join ? IP_ADD_MEMBERSHIP : IP_DROP_MEMBERSHIP, (char *) &mreq, sizeof (mreq));
  }
  return (rc == -1) ? os_getErrno() : 0;
}

#ifdef DDSI_INCLUDE_SSM
static int joinleave_ssm_mcgroup (os_socket socket, int join, const nn_locator_t *srcloc, const nn_locator_t *mcloc, const struct nn_interface *interf)
{
  int rc;
  os_sockaddr_storage mcip, srcip;
  ddsi_ipaddr_from_loc(&mcip, mcloc);
  ddsi_ipaddr_from_loc(&srcip, srcloc);
#if OS_SOCKET_HAS_IPV6
  if (config.transport_selector == TRANS_UDP6)
  {
    struct group_source_req gsr;
    memset (&gsr, 0, sizeof (gsr));
    gsr.gsr_interface = interf ? interf->if_index : 0;
    memcpy (&gsr.gsr_group, &mcip, sizeof (gsr.gsr_group));
    memcpy (&gsr.gsr_source, &srcip, sizeof (gsr.gsr_source));
    rc = os_sockSetsockopt (socket, IPPROTO_IPV6, join ? MCAST_JOIN_SOURCE_GROUP : MCAST_LEAVE_SOURCE_GROUP, &gsr, sizeof (gsr));
  }
  else
#endif
  {
    struct ip_mreq_source mreq;
    memset (&mreq, 0, sizeof (mreq));
    mreq.imr_sourceaddr = ((os_sockaddr_in *) &srcip)->sin_addr;
    mreq.imr_multiaddr = ((os_sockaddr_in *) &mcip)->sin_addr;
    if (interf)
      memcpy (&mreq.imr_interface, interf->loc.address + 12, sizeof (mreq.imr_interface));
    else
      mreq.imr_interface.s_addr = INADDR_ANY;
    rc = os_sockSetsockopt (socket, IPPROTO_IP, join ? IP_ADD_SOURCE_MEMBERSHIP : IP_DROP_SOURCE_MEMBERSHIP, &mreq, sizeof (mreq));
  }
  return (rc == -1) ? os_getErrno() : 0;
}
#endif

static int ddsi_udp_join_mc (ddsi_tran_conn_t conn, const nn_locator_t *srcloc, const nn_locator_t *mcloc, const struct nn_interface *interf)
{
  ddsi_udp_conn_t uc = (ddsi_udp_conn_t) conn;
  (void)srcloc;
#ifdef DDSI_INCLUDE_SSM
  if (srcloc)
    return joinleave_ssm_mcgroup(uc->m_sock, 1, srcloc, mcloc, interf);
  else
#endif
    return joinleave_asm_mcgroup(uc->m_sock, 1, mcloc, interf);
}

static int ddsi_udp_leave_mc (ddsi_tran_conn_t conn, const nn_locator_t *srcloc, const nn_locator_t *mcloc, const struct nn_interface *interf)
{
  ddsi_udp_conn_t uc = (ddsi_udp_conn_t) conn;
  (void)srcloc;
#ifdef DDSI_INCLUDE_SSM
  if (srcloc)
    return joinleave_ssm_mcgroup(uc->m_sock, 0, srcloc, mcloc, interf);
  else
#endif
    return joinleave_asm_mcgroup(uc->m_sock, 0, mcloc, interf);
}

static void ddsi_udp_release_conn (ddsi_tran_conn_t conn)
{
  ddsi_udp_conn_t uc = (ddsi_udp_conn_t) conn;
  nn_log
  (
    LC_INFO,
    "ddsi_udp_release_conn %s socket %d port %d\n",
    conn->m_base.m_multicast ? "multicast" : "unicast",
    uc->m_sock,
    uc->m_base.m_base.m_port
  );
  os_sockFree (uc->m_sock);
#if defined _WIN32 && !defined WINCE
  WSACloseEvent(uc->m_sockEvent);
#endif
  os_free (conn);
}

static int ddsi_udp_is_mcaddr (const ddsi_tran_factory_t tran, const nn_locator_t *loc)
{
  (void) tran;
  switch (loc->kind)
  {
    case NN_LOCATOR_KIND_UDPv4: {
      const struct in_addr *ipv4 = (const struct in_addr *) (loc->address + 12);
      return IN_MULTICAST (ntohl (ipv4->s_addr));
    }
#if OS_SOCKET_HAS_IPV6
    case NN_LOCATOR_KIND_UDPv6: {
      const struct in6_addr *ipv6 = (const struct in6_addr *) loc->address;
      return IN6_IS_ADDR_MULTICAST (ipv6);
    }
#endif
    default: {
      return 0;
    }
  }
}

static enum ddsi_locator_from_string_result ddsi_udp_address_from_string (ddsi_tran_factory_t tran, nn_locator_t *loc, const char *str)
{
  return ddsi_ipaddr_from_string(tran, loc, str, ddsi_udp_factory_g.m_kind);
}

static void ddsi_udp_deinit(void)
{
  if (pa_dec32_nv(&init_g) == 0) {
    if (ddsi_udp_config_g.mship)
      free_group_membership(ddsi_udp_config_g.mship);
    nn_log (LC_INFO | LC_CONFIG, "udp de-initialized\n");
  }
}

int ddsi_udp_init (void)
{
  static c_bool init = FALSE;
  if (! init)
  {
    init = TRUE;
    memset (&ddsi_udp_factory_g, 0, sizeof (ddsi_udp_factory_g));
    ddsi_udp_factory_g.m_free_fn = ddsi_udp_deinit;
    ddsi_udp_factory_g.m_kind = NN_LOCATOR_KIND_UDPv4;
    ddsi_udp_factory_g.m_typename = "udp";
    ddsi_udp_factory_g.m_default_spdp_address = "udp/239.255.0.1";
    ddsi_udp_factory_g.m_connless = TRUE;
    ddsi_udp_factory_g.m_supports_fn = ddsi_udp_supports;
    ddsi_udp_factory_g.m_create_conn_fn = ddsi_udp_create_conn;
    ddsi_udp_factory_g.m_release_conn_fn = ddsi_udp_release_conn;
    ddsi_udp_factory_g.m_join_mc_fn = ddsi_udp_join_mc;
    ddsi_udp_factory_g.m_leave_mc_fn = ddsi_udp_leave_mc;
    ddsi_udp_factory_g.m_is_mcaddr_fn = ddsi_udp_is_mcaddr;
    ddsi_udp_factory_g.m_is_nearby_address_fn = ddsi_ipaddr_is_nearby_address;
    ddsi_udp_factory_g.m_locator_from_string_fn = ddsi_udp_address_from_string;
    ddsi_udp_factory_g.m_locator_to_string_fn = ddsi_ipaddr_to_string;
#if OS_SOCKET_HAS_IPV6
    if (config.transport_selector == TRANS_UDP6)
    {
      ddsi_udp_factory_g.m_kind = NN_LOCATOR_KIND_UDPv6;
      ddsi_udp_factory_g.m_typename = "udp6";
      ddsi_udp_factory_g.m_default_spdp_address = "udp6/ff02::ffff:239.255.0.1";
    }
#endif

    ddsi_factory_add (&ddsi_udp_factory_g);

    ddsi_udp_config_g.mship = new_group_membership();

    nn_log (LC_INFO | LC_CONFIG, "udp initialized\n");
  }
  return 0;
}

/* SHA1 not available (unoffical build.) */
