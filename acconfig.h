/* Define if your raw sockets have arguments in host order as in BSD.  */
#undef BSD_RAWSOCK_ORDER

/* Define if your system knows about struct sockaddr_storage */
#undef HAVE_SOCKADDR_STORAGE

/* Define to int if your system does not know about sa_family_t */
#undef sa_family_t

/* Define to int if your system does not know about socklen_t */
#undef socklen_t

/* Define to `unsigned long long' if <sys/types.h> doesn't define.  */
#undef u_int64_t

/* Define to `unsigned int' if <sys/types.h> doesn't define.  */
#undef u_int32_t

/* Define to `unsigned short' if <sys/types.h> doesn't define.  */
#undef u_int16_t

/* Define to `unsigned char' if <sys/types.h> doesn't define.  */
#undef u_int8_t

/* Undefine if <netdb.h> contains this, otherwise define to 1 */
#undef NI_NUMERICHOST

/* Undefine if <netdb.h> contains this, otherwise define to 1 */
#undef NI_MAXHOST

/* Undefine if <netdb.h> contains this, otherwise define to 32 */
#undef NI_MAXSERV

/* Take care of getaddrinfo */
#undef HAVE_STRUCT_ADDRINFO
#ifndef AI_PASSIVE
# define AI_PASSIVE        1
# define AI_CANONNAME      2
#endif
#ifndef EAI_NODATA
#define EAI_NODATA      1
#define EAI_MEMORY      2
#endif

#ifndef HAVE_STRUCT_ADDRINFO
struct addrinfo {
	int	ai_flags;	/* AI_PASSIVE, AI_CANONNAME */
	int	ai_family;	/* PF_xxx */
	int	ai_socktype;	/* SOCK_xxx */
	int	ai_protocol;	/* 0 or IPPROTO_xxx for IPv4 and IPv6 */
	size_t	ai_addrlen;	/* length of ai_addr */
	char	*ai_canonname;	/* canonical name for hostname */
	struct sockaddr *ai_addr;	/* binary address */
	struct addrinfo *ai_next;	/* next structure in linked list */
};
#endif /* !HAVE_STRUCT_ADDRINFO */

#ifndef HAVE_GETADDRINFO
int getaddrinfo(const char *hostname, const char *servname, 
                const struct addrinfo *hints, struct addrinfo **res);
#endif /* !HAVE_GETADDRINFO */

/* Define if timeradd is defined in <sys/time.h> */
#undef HAVE_TIMERADD
#ifndef HAVE_TIMERADD
#define timeradd(tvp, uvp, vvp)                                         \
        do {                                                            \
                (vvp)->tv_sec = (tvp)->tv_sec + (uvp)->tv_sec;          \
                (vvp)->tv_usec = (tvp)->tv_usec + (uvp)->tv_usec;       \
                if ((vvp)->tv_usec >= 1000000) {                        \
                        (vvp)->tv_sec++;                                \
                        (vvp)->tv_usec -= 1000000;                      \
                }                                                       \
        } while (0)
#define	timersub(tvp, uvp, vvp)						\
	do {								\
		(vvp)->tv_sec = (tvp)->tv_sec - (uvp)->tv_sec;		\
		(vvp)->tv_usec = (tvp)->tv_usec - (uvp)->tv_usec;	\
		if ((vvp)->tv_usec < 0) {				\
			(vvp)->tv_sec--;				\
			(vvp)->tv_usec += 1000000;			\
		}							\
	} while (0)
#endif /* !HAVE_TIMERADD */

/* Define if fd_mask is defined in <sys/select.h> */
#undef HAVE_FDMASK_IN_SELECT
