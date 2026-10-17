#ifndef INCLUDED_cloak_h
#define INCLUDED_cloak_h
/** @file
 * @brief Keyed hostname cloaking for IPv4 and IPv6 client addresses.
 */
#include <stddef.h>

struct Client;
struct irc_in_addr;

extern int cloak_address(const struct irc_in_addr *addr, char *out, size_t outlen);
extern int cloak_hostname(const char *hostname, const struct irc_in_addr *addr,
                          char *out, size_t outlen);
extern int cloak_client(struct Client *cptr);

#endif /* INCLUDED_cloak_h */
