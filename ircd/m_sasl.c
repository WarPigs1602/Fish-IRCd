/*
 * IRC - Internet Relay Chat, ircd/m_sasl.c
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
 *
 */

/*
 * m_functions execute protocol messages on this server:
 *
 *    cptr    is always NON-NULL, pointing to a *LOCAL* client
 *            structure (with an open socket connected!). This
 *            identifies the physical socket where the message
 *            originated (or which caused the m_function to be
 *            executed--some m_functions may call others...).
 *
 *    sptr    is the source of the message, defined by the
 *            prefix part of the message if present. If not
 *            or prefix not found, then sptr==cptr.
 *
 *            (!IsServer(cptr)) => (cptr == sptr), because
 *            prefixes are taken *only* from servers...
 *
 *            (IsServer(cptr))
 *                    (sptr == cptr) => the message didn't
 *                    have the prefix.
 *
 *                    (sptr != cptr && IsServer(sptr) means
 *                    the prefix specified servername. (?)
 *
 *                    (sptr != cptr && !IsServer(sptr) means
 *                    that message originated from a remote
 *                    user (not local).
 *
 *            combining
 *
 *            (!IsServer(sptr)) means that, sptr can safely
 *            taken as defining the target structure of the
 *            message in this server.
 *
 *    *Always* true (if 'parse' and others are working correct):
 *
 *    1)      sptr->from == cptr  (note: cptr->from == cptr)
 *
 *    2)      MyConnect(sptr) <=> sptr == cptr (e.g. sptr
 *            *cannot* be a local connection, unless it's
 *            actually cptr!). [MyConnect(x) should probably
 *            be defined as (x == x->from) --msa ]
 *
 *    parc    number of variable parameter strings (if zero,
 *            parv is allowed to be NULL)
 *
 *    parv    a NULL terminated list of parameter pointers,
 *
 *                    parv[0], sender (prefix string), if not present
 *                            this points to an empty string.
 *                    parv[1]...parv[parc-1]
 *                            pointers to additional parameters
 *                    parv[parc] == NULL, *always*
 *
 *            note:   it is guaranteed that parv[0]..parv[parc-1] are all
 *                    non-NULL pointers.
 */
#include "config.h"

#include "client.h"
#include "capab.h"
#include "ircd.h"
#include "ircd_events.h"
#include "ircd_log.h"
#include "ircd_netconf.h"
#include "ircd_reply.h"
#include "ircd_string.h"
#include "msg.h"
#include "numeric.h"
#include "numnicks.h"
#include "sasl.h"
#include "send.h"
#include "s_debug.h"

#include <stdlib.h>

/** SASL timeout callback - called when a SASL session times out
 * @param[in] ev Timer event (contains client pointer in timer data)
 */
static void sasl_timeout_callback(struct Event* ev)
{
  struct Client* cptr;
  
  assert(0 != ev_timer(ev));
  assert(0 != t_data(ev_timer(ev)));
  
  if (ev_type(ev) == ET_EXPIRE) {
    cptr = (struct Client*) t_data(ev_timer(ev));
    
    /* Verify the client is still valid */
    if (!cptr || cli_magic(cptr) != CLIENT_MAGIC || !MyConnect(cptr))
      return;
      
    /* Verify the client still has an active SASL session */
    if (!cli_sasl(cptr))
      return;
      
    Debug((DEBUG_DEBUG, "SASL timeout for client %s (cookie: %lu)",
           cli_name(cptr), cli_sasl(cptr)));
    
    /* Notify services as well, so an unfinished exchange can be discarded. */
    sasl_send_abort(cptr);
    send_reply(cptr, ERR_SASLFAIL, "Authentication timed out");
    
    /* Clear SASL session */
    sasl_stop_timeout(cptr);
    sasl_session_remove(cli_sasl(cptr));
    cli_sasl(cptr) = 0;
  }
}

/** Start the SASL timeout timer for a client
 * @param[in] cptr Client to set timeout for
 */
static void sasl_start_timeout(struct Client* cptr)
{
  struct Timer* timer;
  
  assert(cptr != NULL);
  assert(MyConnect(cptr));
  assert(cli_sasl(cptr) != 0); /* Should have active SASL session */

  timer = cli_sasl_timer(cptr);
  
  /* Timer should not already be active */
  assert(!t_active(timer));

  /* Start timer */
  timer_add(timer_init(timer), sasl_timeout_callback, (void*) cptr,
            TT_RELATIVE, netconf_int(NETCONF_SASL_TIMEOUT));

  Debug((DEBUG_DEBUG, "SASL timeout started for client %s (%d seconds)",
         cli_name(cptr), netconf_int(NETCONF_SASL_TIMEOUT)));
}

int m_sasl(struct Client* cptr, struct Client* sptr, int parc, char* parv[])
{
  struct Client* acptr;
  const char* target;
  static unsigned long routing_ticker = 0;

  if (parc < 2 || *parv[1] == '\0')
    return need_more_params(sptr, "AUTHENTICATE");

  if (!CapHas(cli_active(cptr), CAP_SASL))
    return 0;

  /* A final '+' can already be in flight when services completes SASL. */
  if (HasFlag(sptr, FLAG_SASL) && !cli_sasl(cptr)
      && strcmp(parv[1], "+") == 0)
    return 0;

  /* IAuth can set a provisional account before registration. SASL may
   * replace that account, but a completed SASL or registered login cannot. */
  if (HasFlag(sptr, FLAG_SASL)
      || (IsUser(sptr) && HasFlag(sptr, FLAG_ACCOUNT)))
    return send_reply(cptr, ERR_SASLALREADY);

  if (strlen(parv[1]) > 400)
    return send_reply(cptr, ERR_SASLTOOLONG);
 
  if (strcmp(parv[1], "*") == 0) {
    if (cli_sasl(cptr)) {
      sasl_send_abort(cptr);
      sasl_stop_timeout(cptr);
      sasl_session_remove(cli_sasl(cptr));
      cli_sasl(cptr) = 0;
    }
    send_reply(cptr, ERR_SASLABORTED);
    return 0;
  }

  acptr = *sasl_server() ? find_match_server((char*)sasl_server()) : NULL;
  if (!sasl_available() || !acptr)
    return send_reply(cptr, ERR_SASLFAIL, "The login server is currently disconnected.  Please excuse the inconvenience.");

  /* Is this the initial authentication challenge? */
  if (!cli_sasl(cptr)) {
    if (!sasl_mechanism_supported(parv[1]))
      return send_reply(cptr, RPL_SASLMECHS, netconf_str(NETCONF_SASL_MECHANISMS));

    do {
      ++routing_ticker;
    } while (!routing_ticker || find_sasl_client(routing_ticker));
    
    cli_sasl(cptr) = routing_ticker;
    sasl_session_add(routing_ticker, cptr);

    Debug((DEBUG_DEBUG, "SASL session started for %s (cookie: %lu)",
           cli_name(cptr), cli_sasl(cptr)));

    /* Start timeout for new session */
    sasl_start_timeout(cptr);
  }

  target = sasl_session_target((unsigned long)cli_sasl(cptr));
  assert(target != NULL);
  sendcmdto_one(&me, CMD_AUTHENTICATE, acptr, "%s %s %s", target,
                sasl_session_host((unsigned long)cli_sasl(cptr)),
                parv[1]);

  return 0;
}

