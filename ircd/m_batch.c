/*
 * IRC - Internet Relay Chat, ircd/m_batch.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 */
/** @file
 * @brief IRCv3 BATCH command relay
 */

#include "config.h"

#include "capab.h"
#include "client.h"
#include "ircd.h"
#include "ircd_features.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "msg.h"
#include "send.h"

#include <string.h>

static int
batch_ref_valid(const char *ref)
{
  const unsigned char *p = (const unsigned char *)ref;

  if (!p || (*p != '+' && *p != '-') || !p[1])
    return 0;

  for (++p; *p; ++p) {
    if (!((*p >= 'a' && *p <= 'z')
          || (*p >= 'A' && *p <= 'Z')
          || (*p >= '0' && *p <= '9')
          || *p == '-'))
      return 0;
  }
  return 1;
}

static int
batch_format_params(char *buf, size_t buflen, int parc, char *parv[])
{
  int added;
  size_t used;
  int i;

  if (parv[1][0] == '-') {
    added = ircd_snprintf(0, buf, buflen, "%s", parv[1]);
    return added >= 0 && (size_t)added < buflen;
  }

  added = ircd_snprintf(0, buf, buflen, "%s %s", parv[1], parv[2]);
  if (added < 0 || (size_t)added >= buflen)
    return 0;
  used = (size_t)added;

  for (i = 3; i < parc; ++i) {
    size_t remaining = buflen - used;
    const char *format = (i == parc - 1
                          && (!*parv[i] || strchr(parv[i], ' ')))
      ? " :%s" : " %s";
    added = ircd_snprintf(0, buf + used, remaining,
                          format, parv[i]);
    if (added < 0 || (size_t)added >= remaining)
      return 0;
    used += (size_t)added;
  }

  return 1;
}

int
ms_batch(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  char params[BUFSIZE];
  struct Client *acptr;

  if (!IsServer(sptr))
    return protocol_violation(cptr, "%s sent BATCH without a server prefix",
                              cli_name(sptr));

  if (parc < 2 || !batch_ref_valid(parv[1])
      || (parv[1][0] == '+' && (parc < 3 || !*parv[2]))
      || (parv[1][0] == '-' && parc != 2))
    return protocol_violation(cptr, "%s sent an invalid BATCH",
                              cli_name(sptr));

  if (!batch_format_params(params, sizeof(params), parc, parv))
    return protocol_violation(cptr, "%s sent an oversized BATCH",
                              cli_name(sptr));

  if (feature_bool(FEAT_NETWORK_FEATURES))
    sendcmdto_flag_serv_butone(sptr, CMD_BATCH, cptr, FLAG_LAST_FLAG, FLAG_SERVICE,
                               "%s", params);

  for (acptr = GlobalClientList; acptr; acptr = cli_next(acptr)) {
    if (MyUser(acptr) && CapActive(acptr, CAP_BATCH))
      sendcmdto_one(sptr, CMD_BATCH, acptr, "%s", params);
  }

  return 0;
}
