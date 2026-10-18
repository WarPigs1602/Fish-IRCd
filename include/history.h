#ifndef INCLUDED_history_h
#define INCLUDED_history_h
/*
 * IRC - Internet Relay Chat, include/history.h
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 */
/** @file
 * @brief Per-channel message history for channel mode +H and CHATHISTORY
 */
#ifndef INCLUDED_ircd_defs_h
#include "ircd_defs.h"
#endif
#ifndef INCLUDED_time_h
#include <time.h>
#define INCLUDED_time_h
#endif

struct Client;
struct Channel;

/** A single stored channel message. */
struct HistEntry {
  struct HistEntry *next;                    /**< Next (newer) entry. */
  time_t ts;                                 /**< Time the message was sent. */
  int notice;                                /**< Non-zero for NOTICE. */
  char msgid[20];                            /**< Network-stable message id. */
  char prefix[NICKLEN + USERLEN + HOSTLEN + 3]; /**< nick!user\@host of sender. */
  char text[1];                              /**< Message text (allocated). */
};

/** Parse a +H parameter "lines:duration" (duration is Nh or Nd).
 * @return Non-zero on success. */
extern int history_parse_param(const char *arg, unsigned int *lines,
                               unsigned int *hours);
/** Format a +H parameter; days are used when \a hours divides evenly. */
extern void history_format_param(char *buf, size_t buflen,
                                 unsigned int lines, unsigned int hours);
/** Record a channel PRIVMSG/NOTICE if \a chptr has +H set. */
extern void history_record(struct Channel *chptr, struct Client *sptr,
                           int notice, const char *text);
/** Drop entries exceeding the +H limits of \a chptr. */
extern void history_prune(struct Channel *chptr);
/** Drop all stored history of \a chptr. */
extern void history_clear(struct Channel *chptr);
/** Format \a t as ISO-8601 UTC with milliseconds. */
extern void history_format_time(char *buf, size_t buflen, time_t t);
/** Parse an ISO-8601 UTC time ("YYYY-MM-DDThh:mm:ss[.fff]Z").
 * @return Non-zero on success. */
extern int history_parse_time(const char *str, time_t *t);
/** Replay history to a freshly joined client (see m_chathistory.c). */
extern void history_replay(struct Client *sptr, struct Channel *chptr);
/** Send the stored history of \a chptr to the server \a cptr during a burst. */
extern void history_burst(struct Client *cptr, struct Channel *chptr);

#endif /* INCLUDED_history_h */
