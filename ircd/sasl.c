/*
 * IRC - Internet Relay Chat, ircd/sasl.c
 * Copyright (C) 2025 MrIron <mriron@undernet.org>
 *
 * See file AUTHORS in IRC package for additional names of
 * the programmers.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 1, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "config.h"

#include "sasl.h"
#include "client.h"
#include "ircd.h"
#include "ircd_alloc.h"
#include "ircd_events.h"
#include "ircd_log.h"
#include "ircd_string.h"
#include "ircd_snprintf.h"
#include "ircd_reply.h"
#include "ircd_netconf.h"
#include "ircd_features.h"
#include "hash.h"
#include "send.h"
#include "msg.h"
#include "capab.h"
#include "numnicks.h"
#include "s_auth.h"
#include "s_debug.h"
#include "s_bsd.h"
#include "numeric.h"
#include "s_user.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

/*** SASL session hash table for cookie->client mapping
 *
 * This table maps SASL session cookies (unsigned long) to client pointers.
 * It is used to efficiently look up a client by its SASL cookie during authentication.
 *
 * The table uses separate chaining for collision resolution and is fixed at 256 buckets.
 * Only used internally to sasl.c.
 */
#define SASL_HASH_SIZE 256

/** Entry in the SASL session hash table. */
struct SaslSessionEntry {
  unsigned long cookie;              /**< SASL session cookie (key) */
  struct Client* client;             /**< Pointer to associated client */
  char target[64];                   /**< Stable native SASL destination */
  char host[HOSTLEN + 1];            /**< Host sent in the original request */
  struct SaslSessionEntry* next;     /**< Next entry in the bucket (chaining) */
};

/** SASL statistics */
struct SaslStats {
  unsigned long auth_success; /**< Number of successful authentications */
  unsigned long auth_failed;  /**< Number of failed authentications */
};

/** Hash table of SASL session entries. */
static struct SaslSessionEntry* sasl_session_table[SASL_HASH_SIZE];

/** Global SASL statistics */
static struct SaslStats sasl_statistics = { 0, 0 };

/** Network configuration overrides the local snircd-style feature. */
const char* sasl_server(void)
{
  const char* server = netconf_str(NETCONF_SASL_SERVER);
  const char* fallback = feature_str(FEAT_SASL_SERVER);

  return *server ? server : fallback ? fallback : "";
}

/** Check if SASL is available. */
int sasl_available(void)
{
  if (!*sasl_server()
      || !find_match_server((char*)sasl_server()))
    return 0;

  return 1;
}

/** Check if a mechanism exists in a mechanism list
 * @param[in] mechanism The mechanism to find
 * @param[in] mechanism_list Comma-delimited list of mechanisms
 * @return 1 if found, 0 if not
 */
static int mechanism_in_list(const char* mechanism, const char* mechanism_list)
{
  char* mech_list;
  char* token;
  int found = 0;

  if (!mechanism_list || !*mechanism_list || !mechanism || !*mechanism)
    return 0;

  DupString(mech_list, mechanism_list);
  if (!mech_list)
    return 0;

  token = strtok(mech_list, ",");
  while (token) {
    /* Trim whitespace */
    while (*token == ' ') token++;
    char* end = token + strlen(token) - 1;
    while (end > token && *end == ' ') *end-- = '\0';
    
    if (ircd_strcmp(token, mechanism) == 0) {
      found = 1;
      break;
    }
    token = strtok(NULL, ",");
  }
  
  MyFree(mech_list);
  return found;
}

/** Check if a SASL mechanism is supported
 * @param[in] mechanism The mechanism to check
 * @return 1 if supported, 0 if not
 */
int sasl_mechanism_supported(const char* mechanism)
{
  /* A service configured through SASL_SERVER may publish no mechanism list.
   * In that case services validates the requested mechanism itself. */
  if (!*netconf_str(NETCONF_SASL_MECHANISMS))
    return 1;
  return mechanism_in_list(mechanism, netconf_str(NETCONF_SASL_MECHANISMS));
}

/** Check and update SASL capability availability
 * This function should be called when events occur that might change
 * SASL availability (netjoin/netsplit, config changes)
 */
void sasl_check_capability(void)
{
  /* Keep the advertised mechanism list in sync with the configuration. */
  cap_set_value(E_CAP_SASL, netconf_str(NETCONF_SASL_MECHANISMS));
  cap_update_availability(E_CAP_SASL, sasl_available());
}

/** Config change callback for SASL-related configuration
 * @param[in] key Configuration key that changed
 * @param[in] old_value Old value (NULL if new key)
 * @param[in] new_value New value
 */
static void sasl_config_callback(const char *key, const char *old_value, const char *new_value)
{
  Debug((DEBUG_DEBUG, "SASL config changed: %s = %s (was: %s)",
         key, new_value ? new_value : "(unset)",
         old_value ? old_value : "(unset)"));
  
  /* Update SASL capability value and availability */
  sasl_check_capability();
  
  /* Re-notify cap-notify clients when the mechanism list changes while
   * SASL is available, so they learn the supported mechanisms. */
  if (ircd_strcmp(key, "sasl.mechanisms") == 0
      && sasl_available()
      && ircd_strcmp(old_value ? old_value : "",
                     new_value ? new_value : "") != 0)
    cap_new(E_CAP_SASL);
}

/** Initialize SASL subsystem and register config callbacks */
void sasl_init(void)
{
  config_register_callback("sasl.", sasl_config_callback);
  /* Initialize the SASL capability value from the configuration. */
  cap_set_value(E_CAP_SASL, netconf_str(NETCONF_SASL_MECHANISMS));
}

/** Compute hash bucket index for a given cookie. */
static unsigned int sasl_cookie_hash(unsigned long cookie) {
  return (unsigned int)(cookie % SASL_HASH_SIZE);
}

/** Add a SASL session to the hash table.
 * @param cookie SASL session cookie (key)
 * @param client Pointer to associated client
 */
void sasl_session_add(unsigned long cookie, struct Client* client) {
  struct Client* server;
  if (!cookie || !client) return;
  unsigned int idx = sasl_cookie_hash(cookie);
  struct SaslSessionEntry* entry = (struct SaslSessionEntry*)MyMalloc(sizeof(struct SaslSessionEntry));
  entry->cookie = cookie;
  entry->client = client;
  server = *sasl_server() ? find_match_server((char*)sasl_server()) : NULL;
  if (*cli_name(client) && (IsUser(client) || (server && MyConnect(server))))
    ircd_strncpy(entry->target, cli_name(client), sizeof(entry->target) - 1);
  else
    ircd_snprintf(0, entry->target, sizeof(entry->target), "%s.%lu",
                  cli_yxx(&me), cookie);
  ircd_strncpy(entry->host,
               cli_user(client) && *cli_user(client)->host ?
               cli_user(client)->host : cli_sock_ip(client), HOSTLEN);
  entry->next = sasl_session_table[idx];
  sasl_session_table[idx] = entry;
}

/** Remove a SASL session from the hash table.
 * @param cookie SASL session cookie to remove
 */
void sasl_session_remove(unsigned long cookie) {
  if (!cookie) return;
  unsigned int idx = sasl_cookie_hash(cookie);
  struct SaslSessionEntry **pp = &sasl_session_table[idx], *cur;
  while ((cur = *pp)) {
    if (cur->cookie == cookie) {
      *pp = cur->next;
      MyFree(cur);
      return;
    }
    pp = &cur->next;
  }
}

/** Find a client by its SASL session cookie.
 * @param cookie SASL session cookie to look up
 * @return Pointer to associated client, or NULL if not found
 */
static struct SaslSessionEntry* sasl_session_find(unsigned long cookie)
{
  struct SaslSessionEntry* entry;

  if (!cookie)
    return NULL;
  entry = sasl_session_table[sasl_cookie_hash(cookie)];
  while (entry) {
    if (entry->cookie == cookie)
      return entry;
    entry = entry->next;
  }
  return NULL;
}

struct Client* find_sasl_client(unsigned long cookie)
{
  struct SaslSessionEntry* entry = sasl_session_find(cookie);
  return entry ? entry->client : NULL;
}

/** Return the destination chosen when the exchange was started. */
const char* sasl_session_target(unsigned long cookie)
{
  struct SaslSessionEntry* entry = sasl_session_find(cookie);
  return entry ? entry->target : NULL;
}

const char* sasl_session_host(unsigned long cookie)
{
  struct SaslSessionEntry* entry = sasl_session_find(cookie);
  return entry ? entry->host : NULL;
}

/** Tell the configured service that a local exchange is no longer active. */
void sasl_send_abort(struct Client* cptr)
{
  struct Client* server;
  const char* target;

  if (!cli_sasl(cptr) || !*sasl_server()
      || !(target = sasl_session_target((unsigned long)cli_sasl(cptr))))
    return;
  server = find_match_server((char*)sasl_server());
  if (server)
    sendcmdto_one(&me, CMD_AUTHENTICATE, server, "%s %s *", target,
                  sasl_session_host((unsigned long)cli_sasl(cptr)));
}

/** Fail all pending local SASL sessions because the SASL server is unreachable.
 * Called when the configured SASL server disconnects, so that clients with an
 * exchange in progress are notified immediately instead of waiting for the
 * session timeout to expire.
 */
void sasl_fail_pending_sessions(void)
{
  struct SaslSessionEntry* entry;
  struct SaslSessionEntry* next;
  struct Client* cli;
  int i;

  for (i = 0; i < SASL_HASH_SIZE; i++) {
    entry = sasl_session_table[i];
    while (entry) {
      next = entry->next;
      cli = entry->client;
      if (cli && cli_magic(cli) == CLIENT_MAGIC && MyConnect(cli)
          && cli_sasl(cli) == entry->cookie) {
        Debug((DEBUG_DEBUG, "SASL session failed for %s (cookie: %lu): "
               "server unreachable", cli_name(cli), entry->cookie));
        sasl_stop_timeout(cli);
        sasl_session_remove(entry->cookie);
        cli_sasl(cli) = 0;
        send_reply(cli, ERR_SASLFAIL,
                   "The login server is currently disconnected.  Please excuse the inconvenience.");
      }
      entry = next;
    }
  }
}

/** Relay native SASL requests and deliver replies to their home server. */
int ms_sasl(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client *server, *home, *cli;
  const char *target, *text;
  char *end;
  unsigned long cookie, created, id;
  int cookie_target;
  char account_info[ACCOUNTLEN + 64];

  if (parc < 4 || !IsServer(sptr))
    return 0;

  server = *sasl_server() ? find_match_server((char*)sasl_server()) : NULL;
  if (!server)
    return 0;

  target = parv[1];
  text = parv[3];
  if (!*target || !*parv[2] || !*text || strlen(text) > 400)
    return 0;

  /* A local unregistered nick is usable when services is directly linked;
   * otherwise pre-registration requires a routable server-scoped cookie. */
  cookie_target = strlen(target) >= 4 && target[2] == '.'
      && strchr("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789[]", target[0])
      && strchr("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789[]", target[1])
      && target[3] >= '0' && target[3] <= '9';
  if (cookie_target) {
    errno = 0;
    cookie = strtoul(target + 3, &end, 10);
    if (errno || !cookie || *end)
      return 0;
    home = FindNServer(target);
  } else {
    cli = FindClient(target);
    home = cli && MyConnect(cli) ? &me :
           cli && IsUser(cli) ? cli_user(cli)->server : NULL;
  }
  /* Never flood a credential to discover its destination. */
  if (!home)
    return 0;

  if (sptr != server) {
    /* A request is server-sourced and belongs to its originating server.
     * Do not relay arbitrary users' credentials or a forged service reply. */
    if (parc != 4 || home != sptr || IsMe(server))
      return 0;
    sendcmdto_one(sptr, CMD_AUTHENTICATE, server, "%s %s %s",
                  target, parv[2], text);
    return 0;
  }

  if (!IsMe(home)) {
    if (!ircd_strcmp(text, "S")) {
      if (parc != 7)
        return 0;
      sendcmdto_one(sptr, CMD_AUTHENTICATE, home, "%s %s S %s %s %s",
                    target, parv[2], parv[4], parv[5], parv[6]);
    } else if (!ircd_strcmp(text, "M")) {
      if (parc != 5)
        return 0;
      sendcmdto_one(sptr, CMD_AUTHENTICATE, home, "%s %s M :%s",
                    target, parv[2], parv[4]);
    } else if (parc == 4) {
      sendcmdto_one(sptr, CMD_AUTHENTICATE, home, "%s %s %s",
                    target, parv[2], text);
    }
    return 0;
  }

  if (cookie_target) {
    cli = find_sasl_client(cookie);
  } else {
    cli = FindClient(target);
    cookie = cli && MyConnect(cli) ? (unsigned long)cli_sasl(cli) : 0;
  }
  if (!cli || !cookie || !MyConnect(cli) || cli_sasl(cli) != cookie
      || !sasl_session_target(cookie)
      || ircd_strcmp(sasl_session_target(cookie), target)
      || !CapHas(cli_active(cli), CAP_SASL)
      || (IsUser(cli) && HasFlag(cli, FLAG_ACCOUNT)))
    return 0;

  if (!ircd_strcmp(text, "S")) {
    if (parc != 7 || !*parv[4] || strlen(parv[4]) > ACCOUNTLEN
        || strpbrk(parv[4], " :") != NULL)
      goto invalid_success;
    errno = 0;
    created = strtoul(parv[5], &end, 10);
    if (errno || parv[5][0] < '0' || parv[5][0] > '9'
        || end == parv[5] || *end || (time_t)created < 0
        || (uint64_t)(time_t)created != created)
      goto invalid_success;
    errno = 0;
    id = strtoul(parv[6], &end, 10);
    if (errno || parv[6][0] < '0' || parv[6][0] > '9'
        || end == parv[6] || *end)
      goto invalid_success;

    if (!IsUser(cli)) {
      if (!cli_auth(cli))
        goto invalid_success;
      ircd_snprintf(0, account_info, sizeof(account_info), "%s:%lu:%lu",
                    parv[4], created, id);
      if (auth_set_account(cli_auth(cli), account_info))
        goto invalid_success;
    } else {
      ircd_strncpy(cli_user(cli)->account, parv[4], ACCOUNTLEN);
      cli_user(cli)->acc_create = created;
      cli_user(cli)->acc_id = id;
      sendcmdto_capflag_common_channels_butone(cli, CMD_ACCOUNT, NULL,
                                                CAP_ACCOUNTNOTIFY, 0, "%s", parv[4]);
      hide_hostmask(cli, FLAG_ACCOUNT);
      sendcmdto_serv_butone(&me, CMD_ACCOUNT, NULL, "%C %s %Tu %lu",
                            cli, parv[4], (time_t)cli_user(cli)->acc_create,
                            (unsigned long)cli_user(cli)->acc_id);
      send_reply(cli, RPL_LOGGEDIN, cli_name(cli), cli_user(cli)->username,
                 cli_user(cli)->host, parv[4], parv[4]);
    }
    sasl_stop_timeout(cli);
    sasl_session_remove(cookie);
    cli_sasl(cli) = 0;
    SetFlag(cli, FLAG_SASL);
    send_reply(cli, RPL_SASLSUCCESS);
    sasl_statistics.auth_success++;
  } else if (!ircd_strcmp(text, "F") || !ircd_strcmp(text, "*")) {
    sasl_stop_timeout(cli);
    sasl_session_remove(cookie);
    cli_sasl(cli) = 0;
    if (*text == '*')
      send_reply(cli, ERR_SASLABORTED);
    else {
      send_reply(cli, ERR_SASLFAIL, "SASL authentication failed");
      sasl_statistics.auth_failed++;
    }
  } else if (!ircd_strcmp(text, "M")) {
    if (parc != 5)
      return 0;
    send_reply(cli, RPL_SASLMECHS, parv[4]);
    sasl_stop_timeout(cli);
    sasl_session_remove(cookie);
    cli_sasl(cli) = 0;
  } else if (parc == 4) {
    sendcmdto_one(&me, CMD_AUTHENTICATE, cli, "%s", text);
  }
  return 0;

invalid_success:
  sasl_stop_timeout(cli);
  sasl_session_remove(cookie);
  cli_sasl(cli) = 0;
  send_reply(cli, ERR_SASLFAIL, "Invalid authentication response");
  sasl_statistics.auth_failed++;
  return 0;
}

/** Stop the SASL timeout timer for a client
 * @param[in] cptr Client to stop timeout for
 */
void sasl_stop_timeout(struct Client* cptr)
{
  struct Timer* timer;

  assert(cptr != NULL);
  assert(MyConnect(cptr));

  timer = cli_sasl_timer(cptr);

  /* Only delete if timer exists and is active */
  if (t_active(timer)) {
    timer_del(timer);
    Debug((DEBUG_DEBUG, "SASL timeout stopped for client %s", cli_name(cptr)));
  }
}

/** Generate SASL statistics for /STATS S
 * @param[in] sptr Client requesting statistics
 * @param[in] sd Stats descriptor (unused)
 * @param[in] param Additional parameter (unused)
 */
void sasl_stats(struct Client* sptr, const struct StatDesc* sd, char* param)
{
  if (sasl_available()) {
    send_reply(sptr, SND_EXPLICIT | RPL_STATSDEBUG,
               ":SASL server: %s", sasl_server());
    send_reply(sptr, SND_EXPLICIT | RPL_STATSDEBUG,
               ":SASL mechanisms: %s", netconf_str(NETCONF_SASL_MECHANISMS));
    send_reply(sptr, SND_EXPLICIT | RPL_STATSDEBUG,
               ":SASL timeout: %d", netconf_int(NETCONF_SASL_TIMEOUT));
    send_reply(sptr, SND_EXPLICIT | RPL_STATSDEBUG,
               ":SASL successful auths: %lu", sasl_statistics.auth_success);
    send_reply(sptr, SND_EXPLICIT | RPL_STATSDEBUG,
               ":SASL failed auths: %lu", sasl_statistics.auth_failed);
  } else {
    send_reply(sptr, SND_EXPLICIT | RPL_STATSDEBUG,
               ":SASL not available");
  }
}
