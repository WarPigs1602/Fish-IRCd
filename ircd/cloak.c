/*
 * IRC - Internet Relay Chat, ircd/cloak.c
 *
 * Based on the Nefarious IRCu host hiding (ircd_cloaking.c).
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 */
/** @file
 * @brief Keyed hostname cloaking for IPv4 and IPv6 client addresses.
 *
 * Compatible with the Nefarious scheme:
 *  - IPv4 a.b.c.d  -> ALPHA.BETA.GAMMA.DELTA.<suffix>
 *    (unique for a.b.c.d, a.b.c.*, a.b.*, a.*)
 *  - IPv6          -> ALPHA:BETA:GAMMA:DELTA:<suffix>
 *    (unique for the full address, its first 7 groups, /64 and /32)
 *  - hostname      -> <prefix>-HASH.<last N labels>
 * Each value is a keyed MD5 hash printed in upper case hex.
 * The keys are FEAT_CLOAK_KEY, FEAT_CLOAK_KEY2 and FEAT_CLOAK_KEY3.
 */
#include "config.h"

#include "cloak.h"
#include "client.h"
#include "ircd_chattr.h"
#include "ircd_features.h"
#include "ircd_md5.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "listener.h"
#include "res.h"
#include "s_conf.h"
#include "struct.h"

#include <arpa/inet.h>
#include <string.h>

/** Hash \a body, append \a key to the digest and hash again.
 * @param[out] d Receives the final 16 byte digest.
 */
static void
cloak_md5(const char *body, const char *key, unsigned char d[16])
{
  struct MD5Context ctx;

  MD5Init(&ctx);
  MD5Update(&ctx, (const unsigned char *)body, strlen(body));
  MD5Final(d, &ctx);

  MD5Init(&ctx);
  MD5Update(&ctx, d, 16);
  MD5Update(&ctx, (const unsigned char *)key, strlen(key));
  MD5Final(d, &ctx);
}

/** Keyed hash folded down to 24 bits. */
static unsigned int
cloak_hash24(const char *body, const char *key)
{
  unsigned char d[16];

  cloak_md5(body, key, d);
  return ((unsigned int)(d[0] ^ d[1] ^ d[2] ^ d[3] ^ d[4]) << 16)
    | ((unsigned int)(d[5] ^ d[6] ^ d[7] ^ d[8] ^ d[9] ^ d[10]) << 8)
    | (unsigned int)(d[11] ^ d[12] ^ d[13] ^ d[14] ^ d[15]);
}

/** Keyed hash folded down to 32 bits. */
static unsigned int
cloak_hash32(const char *body, const char *key)
{
  unsigned char d[16];

  cloak_md5(body, key, d);
  return ((unsigned int)(d[0] ^ d[1] ^ d[2] ^ d[3]) << 24)
    | ((unsigned int)(d[4] ^ d[5] ^ d[6] ^ d[7]) << 16)
    | ((unsigned int)(d[8] ^ d[9] ^ d[10] ^ d[11]) << 8)
    | (unsigned int)(d[12] ^ d[13] ^ d[14] ^ d[15]);
}

/** Fetch the three cloak keys; unset secondary keys fall back to the first.
 * @return Zero if no primary key is configured.
 */
static int
cloak_keys(const char **k1, const char **k2, const char **k3)
{
  *k1 = feature_str(FEAT_CLOAK_KEY);
  *k2 = feature_str(FEAT_CLOAK_KEY2);
  *k3 = feature_str(FEAT_CLOAK_KEY3);
  if (EmptyString(*k1))
    return 0;
  if (EmptyString(*k2))
    *k2 = *k1;
  if (EmptyString(*k3))
    *k3 = *k1;
  return 1;
}

/** Produce the cloaked hostname for \a addr.
 * @param[in] addr Client address.
 * @param[out] out Receives the cloaked host.
 * @param[in] outlen Size of \a out.
 * @return Non-zero on success, zero if cloaking is not configured or
 *   the result does not fit.
 */
int
cloak_address(const struct irc_in_addr *addr, char *out, size_t outlen)
{
  const char *k1, *k2, *k3, *suffix;
  char buf[512];
  unsigned int alpha, beta, gamma, delta;
  int n;

  if (!addr || irc_in_addr_unspec(addr) || !cloak_keys(&k1, &k2, &k3))
    return 0;

  if (irc_in_addr_is_ipv4(addr)) {
    unsigned int a = ntohs(addr->in6_16[6]) >> 8;
    unsigned int b = ntohs(addr->in6_16[6]) & 0xff;
    unsigned int c = ntohs(addr->in6_16[7]) >> 8;
    unsigned int d = ntohs(addr->in6_16[7]) & 0xff;

    suffix = feature_str(FEAT_CLOAK_SUFFIX_V4);
    if (EmptyString(suffix))
      return 0;

    ircd_snprintf(0, buf, sizeof(buf), "%s:%u.%u.%u.%u:%s", k2, a, b, c, d, k3);
    alpha = cloak_hash24(buf, k1);
    ircd_snprintf(0, buf, sizeof(buf), "%s:%u.%u.%u:%s", k3, a, b, c, k1);
    beta = cloak_hash24(buf, k2);
    ircd_snprintf(0, buf, sizeof(buf), "%s:%u.%u:%s", k1, a, b, k2);
    gamma = cloak_hash24(buf, k3);
    ircd_snprintf(0, buf, sizeof(buf), "%s:%u:%s:%s", k2, a, k1, k3);
    delta = cloak_hash24(buf, k1);

    n = ircd_snprintf(0, out, outlen, "%X.%X.%X.%X.%s",
                      alpha, beta, gamma, delta, suffix);
  } else {
    unsigned int w[8];
    int i;

    for (i = 0; i < 8; i++)
      w[i] = ntohs(addr->in6_16[i]);

    suffix = feature_str(FEAT_CLOAK_SUFFIX_V6);
    if (EmptyString(suffix))
      return 0;

    ircd_snprintf(0, buf, sizeof(buf), "%s:%x:%x:%x:%x:%x:%x:%x:%x:%s",
                  k2, w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7], k3);
    alpha = cloak_hash24(buf, k1);
    ircd_snprintf(0, buf, sizeof(buf), "%s:%x:%x:%x:%x:%x:%x:%x:%s",
                  k3, w[0], w[1], w[2], w[3], w[4], w[5], w[6], k1);
    beta = cloak_hash24(buf, k2);
    ircd_snprintf(0, buf, sizeof(buf), "%s:%x:%x:%x:%x:%s",
                  k1, w[0], w[1], w[2], w[3], k2);
    gamma = cloak_hash24(buf, k3);
    ircd_snprintf(0, buf, sizeof(buf), "%s:%x:%x:%s:%s",
                  k2, w[0], w[1], k1, k3);
    delta = cloak_hash24(buf, k1);

    n = ircd_snprintf(0, out, outlen, "%X:%X:%X:%X:%s",
                      alpha, beta, gamma, delta, suffix);
  }
  return n > 0 && (size_t)n < outlen;
}

/** Produce the cloaked form of a resolved hostname.
 * The first labels are replaced by PREFIX-HASH and the last
 * FEAT_CLOAK_COMPONENTS labels are kept, e.g. pc1.dyn.example.com becomes
 * Fish-1A2B3C4D.example.com.
 * @param[in] hostname Resolved hostname of the client.
 * @param[in] addr Client address (unused, kept for API compatibility).
 * @param[out] out Receives the cloaked host.
 * @param[in] outlen Size of \a out.
 * @return Non-zero on success, zero if not configured or it does not fit.
 */
int
cloak_hostname(const char *hostname, const struct irc_in_addr *addr,
               char *out, size_t outlen)
{
  const char *k1, *k2, *k3;
  const char *prefix = feature_str(FEAT_CLOAK_PREFIX);
  char lower[HOSTLEN + 1];
  char buf[512];
  const char *p;
  size_t i, len;
  unsigned int alpha;
  int comps = 0, components = feature_int(FEAT_CLOAK_COMPONENTS), n;

  (void)addr;
  if (!cloak_keys(&k1, &k2, &k3) || EmptyString(hostname)
      || EmptyString(prefix))
    return 0;

  len = strlen(hostname);
  if (len > HOSTLEN)
    return 0;
  /* Hostnames are case-insensitive, so hash a canonical form. */
  for (i = 0; i < len; i++)
    lower[i] = (hostname[i] >= 'A' && hostname[i] <= 'Z')
      ? hostname[i] + ('a' - 'A') : hostname[i];
  lower[len] = '\0';

  ircd_snprintf(0, buf, sizeof(buf), "%s:%s:%s", k1, lower, k2);
  alpha = cloak_hash32(buf, k3);

  if (components < 1)
    components = 1;
  for (p = lower; *p; p++) {
    if (*p == '.' && ++comps >= components && IsHostChar(p[1]))
      break;
  }

  if (*p) {
    p++;
    n = ircd_snprintf(0, out, outlen, "%s-%X.%s", prefix, alpha, p);
  } else
    n = ircd_snprintf(0, out, outlen, "%s-%X", prefix, alpha);
  return n > 0 && (size_t)n < outlen;
}

/** Cloak a newly registering local client if its listener asks for it.
 * A client with a resolved hostname gets a cloaked hostname, otherwise
 * its IPv4/IPv6 address is cloaked.  Does nothing if the client already
 * has a fake host.
 * @param[in] cptr Local client being registered.
 * @return Non-zero if the client's host was replaced.
 */
int
cloak_client(struct Client *cptr)
{
  char host[HOSTLEN + 1];
  const char *real;

  if (!MyConnect(cptr) || IsSetHost(cptr) || !cli_listener(cptr)
      || !listener_cloak(cli_listener(cptr)))
    return 0;

  real = cli_user(cptr)->realhost;
  if (!EmptyString(real) && strcmp(real, cli_sock_ip(cptr))) {
    if (!cloak_hostname(real, &cli_ip(cptr), host, sizeof(host)))
      return 0;
  } else if (!cloak_address(&cli_ip(cptr), host, sizeof(host)))
    return 0;

  ircd_strncpy(cli_user(cptr)->host, host, HOSTLEN);
  SetSetHost(cptr);
  return 1;
}
