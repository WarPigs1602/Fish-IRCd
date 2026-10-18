/*
 * IRC - Internet Relay Chat, ircd/history.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 */
/** @file
 * @brief Per-channel message history for channel mode +H and CHATHISTORY
 *
 * Every server that has local members on a channel sees all messages sent
 * to it, so each of them records the history itself.  Message ids are
 * derived from the network-stable message time, the sender, the target and
 * the text, so all servers compute the same id for the same message.
 */
#include "config.h"

#include "history.h"
#include "channel.h"
#include "client.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_features.h"
#include "ircd_snprintf.h"
#include "handlers.h"
#include "msg.h"
#include "msg_tag.h"
#include "parse.h"
#include "send.h"
#include "struct.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
history_parse_param(const char *arg, unsigned int *lines, unsigned int *hours)
{
  char *end;
  unsigned long l, d;

  if (!arg || !*arg)
    return 0;
  l = strtoul(arg, &end, 10);
  if (end == arg || *end != ':')
    return 0;
  arg = end + 1;
  d = strtoul(arg, &end, 10);
  if (end == arg)
    return 0;
  if (*end == 'd' || *end == 'D') {
    if (d > 0xffff / 24)
      d = 0xffff / 24;
    d *= 24;
    ++end;
  } else if (*end == 'h' || *end == 'H') {
    ++end;
  } else if (*end)
    return 0;
  if (*end || !l || !d)
    return 0;
  if (l > 0xffff)
    l = 0xffff;
  if (d > 0xffff)
    d = 0xffff;
  *lines = (unsigned int)l;
  *hours = (unsigned int)d;
  return 1;
}

void
history_format_param(char *buf, size_t buflen, unsigned int lines,
                     unsigned int hours)
{
  if (hours && !(hours % 24))
    ircd_snprintf(0, buf, buflen, "%u:%ud", lines, hours / 24);
  else
    ircd_snprintf(0, buf, buflen, "%u:%uh", lines, hours);
}

void
history_format_time(char *buf, size_t buflen, time_t t)
{
  struct tm tm;

  gmtime_r(&t, &tm);
  ircd_snprintf(0, buf, buflen, "%04d-%02d-%02dT%02d:%02d:%02d.000Z",
                tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                tm.tm_hour, tm.tm_min, tm.tm_sec);
}

int
history_parse_time(const char *str, time_t *t)
{
  int y, mo, d, h, mi, s;
  long era, yoe, doy, doe, days;

  if (!str || sscanf(str, "%4d-%2d-%2dT%2d:%2d:%2d", &y, &mo, &d, &h, &mi,
                     &s) != 6)
    return 0;
  if (mo < 1 || mo > 12 || d < 1 || d > 31 || h < 0 || h > 23 || mi < 0
      || mi > 59 || s < 0 || s > 60)
    return 0;

  /* days since 1970-01-01 (proleptic Gregorian calendar) */
  y -= mo <= 2;
  era = (y >= 0 ? y : y - 399) / 400;
  yoe = y - era * 400;
  doy = (153 * (mo + (mo > 2 ? -3 : 9)) + 2) / 5 + d - 1;
  doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  days = era * 146097 + doe - 719468;

  *t = (time_t)(days * 86400L + h * 3600L + mi * 60L + s);
  return 1;
}

/** Derive a message id (FNV-1a, 64 bit) from the message identity. */
static void
history_make_msgid(char *buf, size_t buflen, time_t ts, const char *nick,
                   const char *target, int notice, const char *text)
{
  static const char hex[] = "0123456789abcdef";
  unsigned long long h = 14695981039346656037ULL;
  char head[128];
  const unsigned char *p;
  int i;

  ircd_snprintf(0, head, sizeof(head), "%u|%s|%s|%d|", (unsigned int)ts,
                nick, target, notice);
  for (p = (const unsigned char *)head; *p; ++p) {
    h ^= *p;
    h *= 1099511628211ULL;
  }
  for (p = (const unsigned char *)text; *p; ++p) {
    h ^= *p;
    h *= 1099511628211ULL;
  }
  if (buflen < 17)
    return;
  for (i = 0; i < 16; ++i)
    buf[i] = hex[(h >> (60 - 4 * i)) & 0xf];
  buf[16] = '\0';
}

static void
history_pop(struct Channel *chptr)
{
  struct HistEntry *e = chptr->hist_head;

  chptr->hist_head = e->next;
  if (!chptr->hist_head)
    chptr->hist_tail = NULL;
  --chptr->hist_count;
  MyFree(e);
}

void
history_prune(struct Channel *chptr)
{
  time_t oldest;

  if (!(chptr->mode.mode & MODE_HISTORY)) {
    history_clear(chptr);
    return;
  }

  oldest = CurrentTime - (time_t)chptr->mode.hist_hours * 3600;
  while (chptr->hist_head
         && (chptr->hist_count > chptr->mode.hist_lines
             || chptr->hist_head->ts < oldest))
    history_pop(chptr);
}

void
history_clear(struct Channel *chptr)
{
  while (chptr->hist_head)
    history_pop(chptr);
}

void
history_record(struct Channel *chptr, struct Client *sptr, int notice,
               const char *text)
{
  struct HistEntry *e;
  struct MsgTag *tag;
  time_t ts = CurrentTime;

  if (!(chptr->mode.mode & MODE_HISTORY) || !chptr->mode.hist_lines)
    return;

  /* Remote messages carry the network-stable time of the origin server. */
  if (!MyUser(sptr) && (tag = msg_tag_find(parse_tags(), "time"))
      && tag->value)
    history_parse_time(tag->value, &ts);

  e = (struct HistEntry *)MyMalloc(sizeof(struct HistEntry) + strlen(text));
  e->next = NULL;
  e->ts = ts;
  e->notice = notice;
  if (IsUser(sptr) && cli_user(sptr))
    ircd_snprintf(0, e->prefix, sizeof(e->prefix), "%s!%s@%s", cli_name(sptr),
                  cli_user(sptr)->username, cli_user(sptr)->host);
  else
    ircd_snprintf(0, e->prefix, sizeof(e->prefix), "%s", cli_name(sptr));
  strcpy(e->text, text);
  history_make_msgid(e->msgid, sizeof(e->msgid), ts, cli_name(sptr),
                     chptr->chname, notice, text);

  if (chptr->hist_tail)
    chptr->hist_tail->next = e;
  else
    chptr->hist_head = e;
  chptr->hist_tail = e;
  ++chptr->hist_count;

  /* Servers without members on the channel never see the message itself,
   * so the origin server hands the entry to the rest of the network. */
  if (MyUser(sptr) && feature_bool(FEAT_NETWORK_FEATURES))
    sendcmdto_flag_serv_butone(&me, CMD_HISTORY, NULL, FLAG_LAST_FLAG,
                               FLAG_SERVICE,
                               "%H %Tu %d %s %s :%s", chptr, ts, notice,
                               e->msgid, e->prefix, e->text);

  history_prune(chptr);
}

void
history_burst(struct Client *cptr, struct Channel *chptr)
{
  struct HistEntry *e;

  if (!feature_bool(FEAT_NETWORK_FEATURES) || IsService(cptr)
      || !(chptr->mode.mode & MODE_HISTORY))
    return;

  history_prune(chptr);
  for (e = chptr->hist_head; e; e = e->next)
    sendcmdto_one(&me, CMD_HISTORY, cptr, "%H %Tu %d %s %s :%s", chptr,
                  e->ts, e->notice, e->msgid, e->prefix, e->text);
}

/** Server-to-server history entry: HISTORY <channel> <ts> <notice> <msgid>
 * <prefix> :<text>.  Stores entries unknown to us (by msgid) in time order
 * and passes them on to the other servers.
 */
int
ms_history(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct Channel *chptr;
  struct HistEntry *e, *prev, *cur;
  time_t ts;

  if (parc < 7 || !feature_bool(FEAT_NETWORK_FEATURES))
    return 0;
  if (!(chptr = FindChannel(parv[1])))
    return 0;
  if (!(chptr->mode.mode & MODE_HISTORY) || !chptr->mode.hist_lines)
    return 0;

  ts = (time_t)strtoul(parv[2], NULL, 10);
  if (!ts || ts > CurrentTime + 86400)
    return 0;
  if (strlen(parv[4]) != 16)
    return 0;

  for (cur = chptr->hist_head; cur; cur = cur->next)
    if (!strcmp(cur->msgid, parv[4])
        || (cur->notice == (atoi(parv[3]) != 0)
            && cur->ts >= ts - 2 && cur->ts <= ts + 2
            && !strcmp(cur->prefix, parv[5]) && !strcmp(cur->text, parv[6])))
      return 0;

  e = (struct HistEntry *)MyMalloc(sizeof(struct HistEntry) + strlen(parv[6]));
  e->ts = ts;
  e->notice = atoi(parv[3]) != 0;
  strcpy(e->msgid, parv[4]);
  ircd_snprintf(0, e->prefix, sizeof(e->prefix), "%s", parv[5]);
  strcpy(e->text, parv[6]);

  for (prev = NULL, cur = chptr->hist_head; cur && cur->ts <= ts;
       prev = cur, cur = cur->next)
    ;
  e->next = cur;
  if (prev)
    prev->next = e;
  else
    chptr->hist_head = e;
  if (!cur)
    chptr->hist_tail = e;
  ++chptr->hist_count;
  history_prune(chptr);

  sendcmdto_flag_serv_butone(sptr, CMD_HISTORY, cptr, FLAG_LAST_FLAG,
                             FLAG_SERVICE,
                             "%H %Tu %d %s %s :%s", chptr, ts, e->notice,
                             parv[4], parv[5], parv[6]);
  return 0;
}
