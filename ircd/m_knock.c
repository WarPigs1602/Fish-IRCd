/*
 * IRC - Internet Relay Chat, ircd/m_knock.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 */
/** @file
 * @brief KNOCK command handler
 */

#include "config.h"

#include "channel.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_reply.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "s_user.h"
#include "send.h"

/** Minimum seconds between two KNOCKs on the same channel. */
#define KNOCK_CHANNEL_DELAY 60

/** Join all parameters after the channel into one reason string. */
static const char *
knock_reason(int parc, char *parv[], char *buf, size_t len)
{
  int i;
  size_t used = 0;

  buf[0] = '\0';
  for (i = 2; i < parc && used < len - 1; i++) {
    if (EmptyString(parv[i]))
      continue;
    used += ircd_snprintf(0, buf + used, len - used, "%s%s",
                          used ? " " : "", parv[i]);
  }
  return used ? buf : "no reason specified";
}

static void
knock_notify(struct Client *sptr, struct Channel *chptr, const char *comment)
{
  struct Membership *member;

  for (member = chptr->members; member; member = member->next_member) {
    if (!MyConnect(member->user) || IsZombie(member) || !IsChanOp(member))
      continue;

    sendcmdto_one(&me, CMD_NOTICE, member->user,
                  "@%H :KNOCK: %s (%s@%s) %s", chptr, cli_name(sptr),
                  visible_username(sptr), cli_user(sptr)->host, comment);
  }
}

int
m_knock(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct Channel *chptr;
  char reason[BUFSIZE];
  const char *comment;

  if (parc < 2 || EmptyString(parv[1]))
    return need_more_params(sptr, "KNOCK");

  comment = knock_reason(parc, parv, reason, sizeof(reason));

  if (!IsChannelName(parv[1]) || !strIsIrcCh(parv[1])) {
    send_reply(sptr, ERR_NOSUCHCHANNEL, parv[1]);
    return 0;
  }

  if (!(chptr = FindChannel(parv[1]))) {
    send_reply(sptr, ERR_CANNOTKNOCK, parv[1], "Channel does not exist!");
    return 0;
  }

  if (chptr->mode.mode & MODE_NOKNOCK) {
    send_reply(sptr, ERR_CANNOTKNOCK, chptr->chname,
               "Channel does not allow KNOCK (+K)");
    return 0;
  }

  if (find_channel_member(sptr, chptr)) {
    send_reply(sptr, ERR_CANNOTKNOCK, chptr->chname, "You're already there!");
    return 0;
  }

  if (!(chptr->mode.mode & MODE_INVITEONLY)) {
    send_reply(sptr, ERR_CANNOTKNOCK, chptr->chname,
               "Channel is not invite only!");
    return 0;
  }

  if (find_ban(sptr, chptr->banlist)) {
    send_reply(sptr, ERR_CANNOTKNOCK, chptr->chname, "You're banned!");
    return 0;
  }

  if (CurrentTime - chptr->knock_last < KNOCK_CHANNEL_DELAY) {
    send_reply(sptr, ERR_CANNOTKNOCK, chptr->chname,
               "You are KNOCK flooding");
    return 0;
  }
  chptr->knock_last = CurrentTime;

  sendcmdto_channel_servers_butone(sptr, CMD_KNOCK, chptr, NULL, SKIP_NONOPS,
                                   "%H :%s", chptr, comment);
  knock_notify(sptr, chptr, comment);
  sendcmdto_one(&me, CMD_NOTICE, sptr, "%C :Knocked on %H", sptr, chptr);
  return 0;
}

int
ms_knock(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct Channel *chptr;
  const char *comment = (parc > 2 && !EmptyString(parv[2]))
                        ? parv[2] : "no reason specified";

  if (IsServer(sptr))
    return protocol_violation(cptr, "Server attempted to KNOCK");

  if (parc < 2 || !IsGlobalChannel(parv[1])
      || !strIsIrcCh(parv[1]))
    return protocol_violation(cptr, "%s sent malformed KNOCK",
                              cli_name(sptr));

  if (!(chptr = FindChannel(parv[1])))
    return 0;

  if (!(chptr->mode.mode & MODE_INVITEONLY)
      || (chptr->mode.mode & MODE_NOKNOCK)
      || find_channel_member(sptr, chptr)
      || find_ban(sptr, chptr->banlist))
    return 0;

  if (CurrentTime - chptr->knock_last < KNOCK_CHANNEL_DELAY)
    return 0;
  chptr->knock_last = CurrentTime;

  sendcmdto_channel_servers_butone(sptr, CMD_KNOCK, chptr, cptr, SKIP_NONOPS,
                                   "%H :%s", chptr, comment);
  knock_notify(sptr, chptr, comment);
  return 0;
}
