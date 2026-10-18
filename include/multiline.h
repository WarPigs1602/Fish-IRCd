#ifndef INCLUDED_multiline_h
#define INCLUDED_multiline_h
/*
 * IRC - Internet Relay Chat, include/multiline.h
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 */
/** @file
 * @brief IRCv3 draft/multiline support and labeled-response capture
 */

struct Client;
struct MsgBuf;
struct MlBatch;

/** Configured max-bytes of a multiline batch. */
extern unsigned int multiline_max_bytes(void);
/** Configured max-lines of a multiline batch (never above 64). */
extern unsigned int multiline_max_lines(void);

/** Release an open client multiline batch. */
extern void multiline_free(struct MlBatch *batch);

/** Consume a PRIVMSG/NOTICE that belongs to an open multiline batch.
 * @return Non-zero if the message was consumed and must not be relayed. */
extern int multiline_intercept(struct Client *sptr, int notice, int parc,
                               char *parv[]);

/** Divert a PRIVMSG/NOTICE destined for a multiline-capable local client
 * while a batch is being delivered.
 * @return Non-zero if the line was captured and must not be sent. */
extern int multiline_capture(struct Client *to, const char *tok,
                             const char *tags, unsigned int taglen,
                             const struct MsgBuf *buf);

/** Start collecting the lines of a labeled-response reply for \a cptr. */
extern void labeled_begin(struct Client *cptr, const char *label);
/** Non-zero while a labeled-response reply is being collected. */
extern int labeled_active(void);
/** Flush the collected reply (ACK, single labeled line or batch). */
extern void labeled_end(struct Client *cptr);
/** Drop the collected reply without sending it. */
extern void labeled_abort(void);
/** Divert a line to \a to into the labeled-response collection.
 * @return Non-zero if the line was captured and must not be sent. */
extern int labeled_capture(struct Client *to, const char *tags,
                           unsigned int taglen, const struct MsgBuf *buf);

#endif /* INCLUDED_multiline_h */
