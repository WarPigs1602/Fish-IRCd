/*
 * IRC - Internet Relay Chat, ircd/m_multiline.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 */
/** @file
 * @brief IRCv3 draft/multiline: client BATCH handling and delivery
 */
#include "config.h"

#include "capab.h"
#include "channel.h"
#include "client.h"
#include "handlers.h"
#include "hash.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_features.h"
#include "ircd_snprintf.h"
#include "ircd_string.h"
#include "msg.h"
#include "msgq.h"
#include "multiline.h"
#include "parse.h"
#include "send.h"

#include <string.h>

#define ML_HARD_LINES 64
#define ML_MAX_TARGET 256

struct MlLine {
  char *text;
  int concat;
};

/** An open client multiline batch. */
struct MlBatch {
  char ref[48];
  int notice;
  int failed;
  char target[ML_MAX_TARGET];
  unsigned int lines;
  unsigned int bytes;
  struct MlLine line[ML_HARD_LINES];
};

/** One capable recipient of the batch being delivered. */
struct MlRcpt {
  struct Client *client;
  unsigned long long mask;
  char pfx[256];
  char sender[96];
  char cmd[16];
  char target[ML_MAX_TARGET];
};

static struct {
  int active;
  unsigned int cur;
  struct MlBatch *batch;
  struct MlRcpt *rcpt;
  unsigned int nrcpt;
  unsigned int caprcpt;
  unsigned int hint;
} ml;

static unsigned int ml_serial;

unsigned int
multiline_max_bytes(void)
{
  int v = feature_int(FEAT_MULTILINE_MAX_BYTES);
  return v < 512 ? 512 : (unsigned int)v;
}

unsigned int
multiline_max_lines(void)
{
  int v = feature_int(FEAT_MULTILINE_MAX_LINES);
  if (v < 1)
    v = 1;
  return v > ML_HARD_LINES ? ML_HARD_LINES : (unsigned int)v;
}

void
multiline_free(struct MlBatch *b)
{
  unsigned int i;

  if (!b)
    return;
  for (i = 0; i < b->lines; ++i)
    if (b->line[i].text)
      MyFree(b->line[i].text);
  MyFree(b);
}

static void
ml_fail(struct Client *sptr, const char *code, const char *ctx, const char *msg)
{
  sendrawto_one(sptr, ":%s FAIL BATCH %s %s :%s", cli_name(&me), code, ctx, msg);
}

static void
ml_drop(struct Client *sptr)
{
  multiline_free(cli_mlbatch(sptr));
  cli_mlbatch(sptr) = NULL;
}

static int
valid_ref(const char *ref)
{
  size_t len = strlen(ref);
  const char *p;

  if (len == 0 || len >= sizeof(((struct MlBatch *)0)->ref))
    return 0;
  for (p = ref; *p; ++p)
    if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
          (*p >= '0' && *p <= '9') || *p == '-' || *p == '_'))
      return 0;
  return 1;
}

int
multiline_intercept(struct Client *sptr, int notice, int parc, char *parv[])
{
  const char *ref = parse_client_batch();
  struct MlBatch *b;
  const char *text;
  size_t len;

  if (!ref[0] || !MyUser(sptr) || !CapActive(sptr, CAP_MULTILINE))
    return 0;

  b = cli_mlbatch(sptr);
  if (!b || strcmp(b->ref, ref)) {
    ml_fail(sptr, "INVALID_REFTAG", ref, "Invalid batch reference tag");
    return 1;
  }
  if (b->failed)
    return 1;

  if (b->notice < 0)
    b->notice = notice;
  if (b->notice != notice || parc < 2 || ircd_strcmp(parv[1], b->target)) {
    ml_fail(sptr, "MULTILINE_INVALID_TARGET", b->target,
            "Message does not match the batch command or target");
    b->failed = 1;
    return 1;
  }

  text = (parc >= 3) ? parv[parc - 1] : "";
  len = strlen(text);

  if (parse_client_concat() && (len == 0 || b->lines == 0)) {
    ml_fail(sptr, "MULTILINE_INVALID", b->ref, "Invalid use of multiline-concat");
    b->failed = 1;
    return 1;
  }
  if (b->lines >= multiline_max_lines()) {
    char num[16];
    ircd_snprintf(0, num, sizeof(num), "%u", multiline_max_lines());
    ml_fail(sptr, "MULTILINE_MAX_LINES", num, "Multiline batch has too many lines");
    b->failed = 1;
    return 1;
  }
  if (b->bytes + len > multiline_max_bytes()) {
    char num[16];
    ircd_snprintf(0, num, sizeof(num), "%u", multiline_max_bytes());
    ml_fail(sptr, "MULTILINE_MAX_BYTES", num, "Multiline batch is too large");
    b->failed = 1;
    return 1;
  }

  b->line[b->lines].text = (char *)MyMalloc(len + 1);
  memcpy(b->line[b->lines].text, text, len + 1);
  b->line[b->lines].concat = parse_client_concat();
  ++b->lines;
  b->bytes += len;
  return 1;
}

int
multiline_capture(struct Client *to, const char *tok, const char *tags,
                  unsigned int taglen, const struct MsgBuf *buf)
{
  struct MlRcpt *r = NULL;
  unsigned int i;
  const char *p, *s;
  size_t n;

  if (!ml.active || !tok || buf->length < 2 || !MyUser(to)
      || !CapActive(to, CAP_MULTILINE) || !CapActive(to, CAP_BATCH))
    return 0;
  if (strcmp(tok, TOK_PRIVATE) && strcmp(tok, TOK_NOTICE))
    return 0;

  for (i = 0; i < ml.nrcpt; ++i) {
    unsigned int k = (ml.hint + i) % ml.nrcpt;
    if (ml.rcpt[k].client == to) {
      r = &ml.rcpt[k];
      ml.hint = k + 1;
      break;
    }
  }
  if (!r) {
    if (ml.nrcpt == ml.caprcpt) {
      unsigned int ncap = ml.caprcpt ? ml.caprcpt * 2 : 32;
      ml.rcpt = (struct MlRcpt *)MyRealloc(ml.rcpt, ncap * sizeof(*ml.rcpt));
      ml.caprcpt = ncap;
    }
    r = &ml.rcpt[ml.nrcpt++];
    memset(r, 0, sizeof(*r));
    r->client = to;
    if (tags && taglen > 0 && taglen < sizeof(r->pfx))
      memcpy(r->pfx, tags, taglen);

    /* ":sender CMD target :text" */
    p = buf->msg;
    if (*p == ':')
      ++p;
    s = strchr(p, ' ');
    if (!s)
      goto bad;
    n = s - p;
    if (n >= sizeof(r->sender))
      goto bad;
    memcpy(r->sender, p, n);
    p = s + 1;
    s = strchr(p, ' ');
    if (!s || (size_t)(s - p) >= sizeof(r->cmd))
      goto bad;
    memcpy(r->cmd, p, s - p);
    p = s + 1;
    s = strchr(p, ' ');
    if (!s || (size_t)(s - p) >= sizeof(r->target))
      goto bad;
    memcpy(r->target, p, s - p);
  }

  if (ml.cur < 64)
    r->mask |= 1ULL << ml.cur;
  return 1;

bad:
  --ml.nrcpt;
  return 0;
}

static void
ml_flush(void)
{
  unsigned int i, k;
  char id[32];
  char tg[96];

  for (i = 0; i < ml.nrcpt; ++i) {
    struct MlRcpt *r = &ml.rcpt[i];
    struct Client *c = r->client;

    if (IsDead(c) || !r->mask)
      continue;
    ircd_snprintf(0, id, sizeof(id), "ml%u", ++ml_serial);
    sendtaggedto_one(c, r->pfx, ":%s BATCH +%s draft/multiline %s",
                     r->sender, id, r->target);
    for (k = 0; k < ml.batch->lines; ++k) {
      struct MlLine *l = &ml.batch->line[k];

      if (l->text[0] && !(r->mask & (1ULL << k)))
        continue;
      ircd_snprintf(0, tg, sizeof(tg), "@batch=%s%s ", id,
                    l->concat ? ";draft/multiline-concat" : "");
      sendtaggedto_one(c, tg, ":%s %s %s :%s", r->sender, r->cmd, r->target,
                       l->text);
    }
    sendtaggedto_one(c, "", ":%s BATCH -%s", r->sender, id);
  }
}

static void
ml_deliver(struct Client *sptr, struct MlBatch *b)
{
  unsigned int k, nonempty = 0;
  char *v[4];

  for (k = 0; k < b->lines; ++k)
    if (b->line[k].text[0])
      ++nonempty;
  if (!nonempty) {
    ml_fail(sptr, "MULTILINE_INVALID", b->ref, "Multiline batch is empty");
    return;
  }

  ml.batch = b;
  ml.nrcpt = 0;
  ml.hint = 0;
  ml.active = (nonempty > 1 || b->lines > 1);

  for (k = 0; k < b->lines && !IsDead(sptr); ++k) {
    if (!b->line[k].text[0])
      continue;
    ml.cur = k;
    v[0] = (char *)cli_name(sptr);
    v[1] = b->target;
    v[2] = b->line[k].text;
    v[3] = NULL;
    if (b->notice)
      m_notice(sptr, sptr, 3, v);
    else
      m_privmsg(sptr, sptr, 3, v);
  }

  ml.active = 0;
  if (!IsDead(sptr))
    ml_flush();
  ml.batch = NULL;
  ml.nrcpt = 0;
}

/** Client BATCH: open or close a draft/multiline batch. */
int
m_batch(struct Client *cptr, struct Client *sptr, int parc, char *parv[])
{
  struct MlBatch *b;
  const char *ref;

  if (!MyUser(sptr) || !CapActive(sptr, CAP_MULTILINE) || parc < 2
      || !parv[1][0] || (parv[1][0] != '+' && parv[1][0] != '-'))
    return 0;
  ref = parv[1] + 1;

  if (parv[1][0] == '+') {
    if (parc < 3 || strcmp(parv[2], "draft/multiline"))
      return 0;
    if (!valid_ref(ref)) {
      ml_fail(sptr, "INVALID_REFTAG", ref, "Invalid batch reference tag");
      return 0;
    }
    if (cli_mlbatch(sptr))
      ml_drop(sptr);
    if (parc < 4 || strlen(parv[3]) >= ML_MAX_TARGET || strchr(parv[3], ',')
        || !(IsChannelName(parv[3]) || FindUser(parv[3]))) {
      ml_fail(sptr, "MULTILINE_INVALID_TARGET", parc < 4 ? "*" : parv[3],
              "Invalid multiline target");
      return 0;
    }
    b = (struct MlBatch *)MyMalloc(sizeof(*b));
    memset(b, 0, sizeof(*b));
    ircd_strncpy(b->ref, ref, sizeof(b->ref) - 1);
    ircd_strncpy(b->target, parv[3], sizeof(b->target) - 1);
    b->notice = -1;
    cli_mlbatch(sptr) = b;
    return 0;
  }

  b = cli_mlbatch(sptr);
  if (!b || strcmp(b->ref, ref)) {
    ml_fail(sptr, "INVALID_REFTAG", ref, "Unknown batch reference tag");
    return 0;
  }
  cli_mlbatch(sptr) = NULL;
  if (!b->failed)
    ml_deliver(sptr, b);
  multiline_free(b);
  return 0;
}
