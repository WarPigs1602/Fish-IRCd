/*
 * IRC - Internet Relay Chat, include/supported.h
 * Copyright (C) 1999 Perry Lorier.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
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
 * $Id$
 *
 * Description: This file has the featureset that Fish-IRCd announces on connecting
 *              a client.  It's in this .h because it's likely to be appended
 *              to frequently and s_user.h is included by basically everyone.
 */
#ifndef INCLUDED_supported_h
#define INCLUDED_supported_h

#include "channel.h"
#include "ircd_defs.h"
#include "ircd_features.h"

/* 
 * 'Features' supported by this ircd
 */
#define FEATURES1 \
                "WHOX"\
                " WALLCHOPS"\
                " WALLVOICES"\
                " USERIP"\
                " CPRIVMSG"\
                " CNOTICE"\
                " KNOCK"\
                " BOT=B" \
                " SILENCE=%i"

/* Limits */
#define FEATURES2 "MODES=%i" \
                " MAXCHANNELS=%i" \
                " MAXBANS=%i" \
                " NICKLEN=%i" \
                " MAXNICKLEN=%i" \
                " TOPICLEN=%i" \
                " AWAYLEN=%i" \
                " KICKLEN=%i" \
                " CHANNELLEN=%i" \
                " MAXCHANNELLEN=%i"

/* Channel and network properties */
#define FEATURES3 "CHANTYPES=%s" \
                " PREFIX=%s" \
                " STATUSMSG=%s" \
                " CHANMODES=%s" \
                " EXCEPTS=e" \
                " CASEMAPPING=%s" \
                " NETWORK=%s" \
                " CLIENTTAGDENY=%s"

#define FEATURESVALUES1 feature_int(FEAT_MAXSILES)

#define FEATURESVALUES2 MAXMODEPARAMS, \
                        feature_int(FEAT_MAXCHANNELSPERUSER), \
                        feature_int(FEAT_MAXBANS), feature_int(FEAT_NICKLEN), \
                        NICKLEN, TOPICLEN, AWAYLEN, TOPICLEN, \
                        feature_int(FEAT_CHANNELLEN), CHANNELLEN

#define FEATURESVALUES3 \
                        (feature_bool(FEAT_LOCAL_CHANNELS) ? "#&" : "#"), "(ov)@+", "@+", \
                        (feature_bool(FEAT_OPLEVELS) \
                        ? "be,AkU,jlH,imnpstrDdRcCuMZK" \
                        :   "be,k,jlH,imnpstrDdRcCuMZK"), \
                        "rfc1459", feature_str(FEAT_NETWORK), \
                        feature_str(FEAT_CLIENTTAGDENY)

#endif /* INCLUDED_supported_h */
