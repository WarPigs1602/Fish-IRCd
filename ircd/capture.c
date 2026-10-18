/*
 * IRC - Internet Relay Chat, ircd/capture.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 */
/** @file
 * @brief IRCv3 labeled-response: collect the replies to one labeled command
 */
#include "config.h"

#include "client.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_defs.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "msgq.h"
#include "multiline.h"
#include "send.h"

#include <string.h>

#define LABELED_MAX_LINES 256

struct LabeledLine {
  char *tags;  /**< Tag section ("@... ") or NULL. */
  char *body;  /**< Message without CRLF. */
};

static struct {
  struct Client *client;
  int active;
  unsigned int count;
  char label[72];            /**< Label in unescaped form. */
  struct LabeledLine line[LABELED_MAX_LINES];
} lc;

static unsigned int labeled_serial;

static char *
dup_n(const char *s, unsigned int len)
{
  char *p = (char *)MyMalloc(len + 1);
  memcpy(p, s, len);
  p[len] = '\0';
  return p;
}

static void
labeled_clear(void)
{
  unsigned int i;

  for (i = 0; i < lc.count; ++i) {
    if (lc.line[i].tags)
      MyFree(lc.line[i].tags);
    MyFree(lc.line[i].body);
    lc.line[i].tags = lc.line[i].body = NULL;
  }
  lc.count = 0;
  lc.active = 0;
  lc.client = NULL;
}

/** Escape a tag value; \a out needs 2 * strlen(in) + 1 bytes. */
static void
escape_value(const char *in, char *out)
{
  for (; *in; ++in) {
    switch (*in) {
    case ';':  *out++ = '\\'; *out++ = ':'; break;
    case ' ':  *out++ = '\\'; *out++ = 's'; break;
    case '\\': *out++ = '\\'; *out++ = '\\'; break;
    case '\r': *out++ = '\\'; *out++ = 'r'; break;
    case '\n': *out++ = '\\'; *out++ = 'n'; break;
    default:   *out++ = *in; break;
    }
  }
  *out = '\0';
}

void
labeled_begin(struct Client *cptr, const char *label)
{
  labeled_clear();
  lc.client = cptr;
  lc.active = 1;
  ircd_strncpy(lc.label, label, sizeof(lc.label) - 1);
  lc.label[sizeof(lc.label) - 1] = '\0';
}

int
labeled_active(void)
{
  return lc.active;
}

void
labeled_abort(void)
{
  labeled_clear();
}

int
labeled_capture(struct Client *to, const char *tags, unsigned int taglen,
                const struct MsgBuf *buf)
{
  struct LabeledLine *ll;

  if (!lc.active || to != lc.client || lc.count >= LABELED_MAX_LINES
      || buf->length < 2)
    return 0;

  ll = &lc.line[lc.count++];
  ll->tags = (tags && taglen) ? dup_n(tags, taglen) : NULL;
  ll->body = dup_n(buf->msg, buf->length - 2);
  return 1;
}

/** Tag section for a replayed line: \a first then the old tags. */
static void
make_tags(char *out, size_t outlen, const char *first, const char *old)
{
  if (old && old[0] == '@' && old[1] != '\0')
    ircd_snprintf(0, out, outlen, "@%s;%s", first, old + 1);
  else
    ircd_snprintf(0, out, outlen, "@%s ", first);
}

void
labeled_end(struct Client *cptr)
{
  char esc[160];
  char first[200];
  char tags[OUTBOUND_TAG_MAX + 256];
  char id[32];
  unsigned int i, n = lc.count;
  struct LabeledLine *ll = lc.line;

  if (!lc.active || cptr != lc.client || IsDead(cptr)) {
    labeled_clear();
    return;
  }
  lc.active = 0;  /* replayed lines must not be captured again */
  escape_value(lc.label, esc);

  if (n == 0) {
    sendtaggedto_one(cptr, "", "@label=%s :%s ACK", esc, cli_name(&me));
  } else if (n == 1) {
    ircd_snprintf(0, first, sizeof(first), "label=%s", esc);
    make_tags(tags, sizeof(tags), first, ll[0].tags);
    sendtaggedto_one(cptr, tags, "%s", ll[0].body);
  } else {
    ircd_snprintf(0, id, sizeof(id), "lr%u", ++labeled_serial);
    sendtaggedto_one(cptr, "", "@label=%s :%s BATCH +%s labeled-response",
                     esc, cli_name(&me), id);
    ircd_snprintf(0, first, sizeof(first), "batch=%s", id);
    for (i = 0; i < n; ++i) {
      make_tags(tags, sizeof(tags), first, ll[i].tags);
      sendtaggedto_one(cptr, tags, "%s", ll[i].body);
    }
    sendtaggedto_one(cptr, "", ":%s BATCH -%s", cli_name(&me), id);
  }
  labeled_clear();
}
