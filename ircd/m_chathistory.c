/*
 * IRC - Internet Relay Chat, ircd/m_chathistory.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 */
/** @file
 * @brief IRCv3 CHATHISTORY command (draft/chathistory)
 *
 * History is kept per channel as configured by channel mode +H
 * (see history.c).  Replies are wrapped in a "chathistory" batch.
 */

#include "config.h"

#include "capab.h"
#include "channel.h"
#include "client.h"
#include "hash.h"
#include "history.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_features.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "msg.h"
#include "send.h"

#include <stdlib.h>
#include <string.h>

/** Position of a selector within the history array:
 * entries [0,lo) are before it, [lo,hi) are at it, [hi,n) are after it. */
struct HistPos {
  unsigned int lo;
  unsigned int hi;
};

static void
chathistory_fail(struct Client *sptr, const char *code, const char *context,
                 const char *text)
{
  sendrawto_one(sptr, ":%s FAIL CHATHISTORY %s %s :%s", cli_name(&me), code,
                context, text);
}

/** Resolve a "timestamp=..." or "msgid=..." selector.
 * @return 1 on success, 0 if the selector is malformed.  An unknown msgid
 * resolves to an empty position at the end of the history. */
static int
chathistory_resolve(const char *sel, struct HistEntry **ents, unsigned int n,
                    struct HistPos *pos)
{
  unsigned int i;

  if (!ircd_strncmp(sel, "timestamp=", 10)) {
    time_t t;

    if (!history_parse_time(sel + 10, &t))
      return 0;
    for (i = 0; i < n && ents[i]->ts < t; ++i)
      ;
    pos->lo = i;
    for (; i < n && ents[i]->ts == t; ++i)
      ;
    pos->hi = i;
    return 1;
  }

  if (!ircd_strncmp(sel, "msgid=", 6) && sel[6]) {
    for (i = 0; i < n; ++i)
      if (!strcmp(ents[i]->msgid, sel + 6)) {
        pos->lo = i;
        pos->hi = i + 1;
        return 1;
      }
    pos->lo = pos->hi = n;
    return 1;
  }

  return 0;
}

static void
chathistory_send(struct Client *sptr, struct Channel *chptr,
                 struct HistEntry **ents, unsigned int start,
                 unsigned int end)
{
  static unsigned int batch_counter;
  char ref[24];
  char tbuf[32];
  int batch = CapActive(sptr, CAP_BATCH);
  unsigned int i;

  ircd_snprintf(0, ref, sizeof(ref), "chathistory%u", ++batch_counter);

  if (batch)
    sendrawto_one(sptr, ":%s BATCH +%s chathistory %s", cli_name(&me), ref,
                  chptr->chname);
  for (i = start; i < end; ++i) {
    char tags[160];
    int len = 0;
    int wm = CapActive(sptr, CAP_MESSAGE_TAGS);
    int wt = wm || CapActive(sptr, CAP_SERVER_TIME);

    /* Tags are built here (not by send_buffer) so that the original message
     * time and msgid are replayed instead of the delivery time. */
    tags[0] = '\0';
    if (batch)
      len += ircd_snprintf(0, tags + len, sizeof(tags) - len, "%sbatch=%s",
                           len ? ";" : "@", ref);
    if (wt) {
      history_format_time(tbuf, sizeof(tbuf), ents[i]->ts);
      len += ircd_snprintf(0, tags + len, sizeof(tags) - len, "%stime=%s",
                           len ? ";" : "@", tbuf);
    }
    if (wm)
      len += ircd_snprintf(0, tags + len, sizeof(tags) - len, "%smsgid=%s",
                           len ? ";" : "@", ents[i]->msgid);
    if (len)
      strcat(tags, " ");

    sendtaggedto_one(sptr, tags, ":%s %s %s :%s", ents[i]->prefix,
                     ents[i]->notice ? "NOTICE" : "PRIVMSG", chptr->chname,
                     ents[i]->text);
  }
  if (batch)
    sendrawto_one(sptr, ":%s BATCH -%s", cli_name(&me), ref);
}

/** Replay the stored history of \a chptr to a client that just joined.
 * Clients with draft/chathistory fetch history themselves and get nothing. */
void
history_replay(struct Client *sptr, struct Channel *chptr)
{
  struct HistEntry *e, **ents;
  unsigned int n, i, max;

  if (!(chptr->mode.mode & MODE_HISTORY) || CapActive(sptr, CAP_CHATHISTORY))
    return;

  history_prune(chptr);
  n = chptr->hist_count;
  if (!n)
    return;
  ents = (struct HistEntry **)MyMalloc(n * sizeof(*ents));
  for (i = 0, e = chptr->hist_head; e && i < n; e = e->next)
    ents[i++] = e;
  n = i;
  max = feature_int(FEAT_CHATHISTORY_MAX);
  chathistory_send(sptr, chptr, ents, max && n > max ? n - max : 0, n);
  MyFree(ents);
}

/*
 * m_chathistory - client message handler
 *
 * parv[1] = subcommand (LATEST, BEFORE, AFTER, AROUND, BETWEEN)
 * parv[2] = target channel
 * parv[3] = selector ("*" allowed for LATEST)
 * parv[4] = limit, or second selector for BETWEEN
 * parv[5] = limit (BETWEEN)
 */
int
m_chathistory(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct Channel *chptr;
  struct Membership *memb;
  struct HistEntry *e, **ents;
  struct HistPos a, b;
  unsigned int n, i, limit, max, start, end;
  const char *sub;
  int between;

  if (!CapActive(sptr, CAP_CHATHISTORY))
    return 0;

  if (parc < 2) {
    chathistory_fail(sptr, "NEED_MORE_PARAMS", "CHATHISTORY",
                     "Missing parameters");
    return 0;
  }
  sub = parv[1];
  between = !ircd_strcmp(sub, "BETWEEN");

  if (ircd_strcmp(sub, "LATEST") && ircd_strcmp(sub, "BEFORE")
      && ircd_strcmp(sub, "AFTER") && ircd_strcmp(sub, "AROUND") && !between) {
    chathistory_fail(sptr, "INVALID_PARAMS", sub, "Unknown subcommand");
    return 0;
  }
  if (parc < (between ? 6 : 5)) {
    chathistory_fail(sptr, "NEED_MORE_PARAMS", sub, "Missing parameters");
    return 0;
  }

  if (!IsChannelName(parv[2]) || !(chptr = FindChannel(parv[2]))
      || !(chptr->mode.mode & MODE_HISTORY)
      || !(memb = find_member_link(chptr, sptr)) || IsZombie(memb)) {
    chathistory_fail(sptr, "INVALID_TARGET", parv[2], "Messages could not be retrieved");
    return 0;
  }

  limit = (unsigned int)strtoul(parv[between ? 5 : 4], NULL, 10);
  max = feature_int(FEAT_CHATHISTORY_MAX);
  if (!limit) {
    chathistory_fail(sptr, "INVALID_PARAMS", sub, "Invalid limit");
    return 0;
  }
  if (max && limit > max)
    limit = max;

  history_prune(chptr);
  n = chptr->hist_count;
  ents = (struct HistEntry **)MyMalloc((n ? n : 1) * sizeof(*ents));
  for (i = 0, e = chptr->hist_head; e && i < n; e = e->next)
    ents[i++] = e;
  n = i;

  start = 0;
  end = n;

  if (!ircd_strcmp(sub, "LATEST") && !strcmp(parv[3], "*")) {
    start = n > limit ? n - limit : 0;
  } else if (!chathistory_resolve(parv[3], ents, n, &a)
             || (between && !chathistory_resolve(parv[4], ents, n, &b))) {
    MyFree(ents);
    chathistory_fail(sptr, "INVALID_PARAMS", sub, "Invalid selector");
    return 0;
  } else if (!ircd_strcmp(sub, "LATEST") || !ircd_strcmp(sub, "AFTER")) {
    start = a.hi;
    if (!ircd_strcmp(sub, "LATEST") && n - start > limit)
      start = n - limit;
    else if (n - start > limit)
      end = start + limit;
  } else if (!ircd_strcmp(sub, "BEFORE")) {
    end = a.lo;
    start = end > limit ? end - limit : 0;
  } else if (!ircd_strcmp(sub, "AROUND")) {
    start = a.lo > limit / 2 ? a.lo - limit / 2 : 0;
    end = start + limit < n ? start + limit : n;
  } else { /* BETWEEN */
    if (a.lo <= b.lo) {
      start = a.hi;
      end = b.lo;
      if (end > start && end - start > limit)
        end = start + limit;
    } else {
      start = b.hi;
      end = a.lo;
      if (end > start && end - start > limit)
        start = end - limit;
    }
    if (end < start)
      end = start;
  }

  chathistory_send(sptr, chptr, ents, start, end);
  MyFree(ents);
  return 0;
}
