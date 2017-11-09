/* This file specifies the lwip features */

#ifndef __LWIPOPTS_H__
#define __LWIPOPTS_H_

#include <stddef.h>

/* enable dual-stack */
#define LWIP_IPV4		1
#define LWIP_IPV6		1

/**
 * SYS_LIGHTWEIGHT_PROT==1: if you want inter-task protection for certain
 * critical regions during buffer allocation, deallocation and memory
 * allocation and deallocation.
 */
#define SYS_LIGHTWEIGHT_PROT	1

/** 
 * NO_SYS==1: Provides VERY minimal functionality. Otherwise,
 * use lwIP facilities.
 */
#define NO_SYS			0

/**
 * LWIP_RAW==1: Enable application layer to hook into the IP layer itself.
 * LWIP_RAW==0: speeds up input processing
 */
#define LWIP_RAW		0

/**
 * LWIP_SOCKET==1: Enable Socket API (require to use sockets.c)
 */
#define LWIP_SOCKET		!(NO_SYS == 1)

/**
 * LWIP_NETCONN==1: Enable Netconn API (require to use api_lib.c)
 */
#define LWIP_NETCONN		!(NO_SYS == 1)

/** LWIP_NETCONN_SEM_PER_THREAD==1: Use one (thread-local) semaphore per
 * thread calling socket/netconn functions instead of allocating one
 * semaphore per netconn (and per select etc.)
 * ATTENTION: a thread-local semaphore for API calls is needed:
 * - LWIP_NETCONN_THREAD_SEM_GET() returning a sys_sem_t*
 * - LWIP_NETCONN_THREAD_SEM_ALLOC() creating the semaphore
 * - LWIP_NETCONN_THREAD_SEM_FREE() freeing the semaphore
 * The latter 2 can be invoked up by calling netconn_thread_init()/netconn_thread_cleanup().
 * Ports may call these for threads created with sys_thread_new().
 */
#define LWIP_NETCONN_SEM_PER_THREAD	0

/**
 * LWIP_NETIF_API==1: Support netif api (in netifapi.c)
 */
#define LWIP_NETIF_API		!(NO_SYS == 1)

/**
 * LWIP_DHCP==1: Enable DHCP module.
 */
#define LWIP_DHCP 		1

/**
 * LWIP_IPV6_DHCP6==1: enable DHCPv6 stateful address autoconfiguration.
 */
#define LWIP_IPV6_DHCP6		1

/**
 * DHCP_DOES_ARP_CHECK==1: Do an ARP check on the offered address.
 */
#define DHCP_DOES_ARP_CHECK	0

/**
 * LWIP_DNS==1: Turn on DNS module. UDP must be available for DNS
 * transport.
 */
#define LWIP_DNS		1

/**
 * LWIP_MDNS_RESPONDER==1: Turn on multicast DNS module. UDP must be available for MDNS
 * transport. IGMP is needed for IPv4 multicast.
 */
#define LWIP_MDNS_RESPONDER	1

#define LWIP_NUM_NETIF_CLIENT_DATA	(LWIP_MDNS_RESPONDER)

/**
 * LWIP_UDP==1: Turn on UDP.
 */
#define LWIP_UDP		1

/**
 * LWIP_UDPLITE==1: Turn on UDP-Lite. (Requires LWIP_UDP)
 */
#define LWIP_UDPLITE		1

#define LWIP_NETBUF_RECVINFO	1

/**
 * LWIP_IGMP==1: Turn on IGMP module.
 */
#define LWIP_IGMP		1

/**
 * ETHARP_TRUST_IP_MAC==1: Incoming IP packets cause the ARP table to be
 * updated with the source MAC and IP addresses supplied in the packet.
 * You may want to disable this if you do not trust LAN peers to have the
 * correct addresses, or as a limited approach to attempt to handle
 * spoofing. If disabled, lwIP will need to make a new ARP request if
 * the peer is not already in the ARP table, adding a little latency.
 * The peer *is* in the ARP table if it requested our address before.
 * Also notice that this slows down input processing of every IP packet!
 */
#define ETHARP_TRUST_IP_MAC	1

/**
 * LWIP_TCP==1: Turn on TCP.
 */
#define LWIP_TCP		1

/**
 * LWIP_TCP_KEEPALIVE==1: Enable TCP_KEEPIDLE, TCP_KEEPINTVL and TCP_KEEPCNT
 * options processing. Note that TCP_KEEPIDLE and TCP_KEEPINTVL have to be set
 * in seconds. (does not require sockets.c, and will affect tcp.c)
 */
#define LWIP_TCP_KEEPALIVE	0

/**
 * LWIP_TCPIP_TIMEOUT==1: Enable tcpip_timeout/tcpip_untimeout tod create
 * timers running in tcpip_thread from another thread.
 */
#define LWIP_TCPIP_TIMEOUT	0

/**
 * LWIP_STATS_DISPLAY==1: Compile in the statistics output functions.
 */
#define LWIP_STATS_DISPLAY	1

/**
 * TCP_MSS: TCP Maximum segment size. (default is 536, a conservative default,
 * you might want to increase this.)
 * For the receive side, this MSS is advertised to the remote side
 * when opening a connection. For the transmit size, this MSS sets
 * an upper limit on the MSS advertised by the remote host.
 */
#define TCP_MSS			1460

/**
 * LWIP_BROADCAST_PING==1: respond to broadcast pings (default is unicast only)
 */
#define LWIP_BROADCAST_PING	1

/**
 * LWIP_MULTICAST_PING==1: respond to multicast pings (default is unicast only)
 */
#define LWIP_MULTICAST_PING	1

/**
 * LWIP_HAVE_LOOPIF==1: Support loop interface (127.0.0.1) and loopif.c
 */
#define LWIP_HAVE_LOOPIF	1

/**
 * LWIP_NETIF_LOOPBACK_MULTITHREADING: Indicates whether threading is enabled in
 * the system, as netifs must change how they behave depending on this setting
 * for the LWIP_NETIF_LOOPBACK option to work.
 * Setting this is needed to avoid reentering non-reentrant functions like
 * tcp_input().
 *    LWIP_NETIF_LOOPBACK_MULTITHREADING==1: Indicates that the user is using a
 *       multithreaded environment like tcpip.c. In this case, netif->input()
 *       is called directly.
 *    LWIP_NETIF_LOOPBACK_MULTITHREADING==0: Indicates a polling (or NO_SYS) setup.
 *       The packets are put on a list and netif_poll() must be called in
 *       the main application loop.
 */
#define LWIP_NETIF_LOOPBACK_MULTITHREADING	!(NO_SYS == 1)

/**
 * LWIP_NETIF_LOOPBACK==1: Support sending packets with a destination IP
 * address equal to the netif IP address, looping them back up the stack.
 */
#define LWIP_NETIF_LOOPBACK	1

/**
 * LWIP_CHECKSUM_ON_COPY==1: Calculate checksum when copying data from
 * application buffers to pbufs.
 */
#define LWIP_CHECKSUM_ON_COPY	1

/**
 * TCPIP_THREAD_PRIO: The priority assigned to the main tcpip thread.
 * The priority value itself is platform-dependent, but is passed to
 * sys_thread_new() when the thread is created.
 */
#define TCPIP_THREAD_PRIO	HIGH_PRIO

/**
 * MEMP_NUM_UDP_PCB: the number of UDP protocol control blocks. One
 * per active UDP "connection".
 * (requires the LWIP_UDP option)
 */
#define MEMP_NUM_UDP_PCB	0x30

/**
 * MEMP_NUM_TCP_PCB: the number of simulatenously active TCP connections.
 * (requires the LWIP_TCP option)
 */
#define MEMP_NUM_TCP_PCB	0x30

/**
 * MEMP_NUM_TCP_PCB_LISTEN: the number of listening TCP connections.
 * (requires the LWIP_TCP option)
 */
#define MEMP_NUM_TCP_PCB_LISTEN	0x30

/**
 * MEMP_NUM_NETCONN: the number of struct netconns.
 * (only needed if you use the sequential API, like api_lib.c)
 * MEM_SIZE: the size of the heap memory. If the application will send
 * a lot of data that needs to be copied, this should be set high.
 */
#define MEMP_NUM_NETCONN	16

/**
 * MEMP_NUM_TCPIP_MSG_API: the number of struct tcpip_msg, which are used
 * for callback/timeout API communication.
 * (only needed if you use tcpip.c)
 */
#define MEMP_NUM_TCPIP_MSG_API	16

/**
 * MEMP_NUM_TCPIP_MSG_INPKT: the number of struct tcpip_msg, which are used
 * for incoming packets.
 * (only needed if you use tcpip.c)
 */
#define MEMP_NUM_TCPIP_MSG_INPKT	16

/**
 * DEFAULT_THREAD_PRIO: The priority assigned to any other lwIP thread.
 * The priority value itself is platform-dependent, but is passed to
 * sys_thread_new() when the thread is created.
 */
#define DEFAULT_THREAD_PRIO	NORMAL_PRIO

/**
 * MEM_SIZE: the size of the heap memory. If the application will send
 * a lot of data that needs to be copied, this should be set high.
 */
#define MEM_SIZE		(16*0x1000)

#ifndef __KERNEL__
#define LWIP_TIMEVAL_PRIVATE		0
#endif

/**
 * LWIP_COMPAT_SOCKETS==1: Enable BSD-style sockets functions names.
 * (only used if you use sockets.c)
 */
#define LWIP_COMPAT_SOCKETS		0

/**
 * LWIP_POSIX_SOCKETS_IO_NAMES==1: Enable POSIX-style sockets functions names.
 * Disable this option if you use a POSIX operating system that uses the same
 * names (read, write & close). (only used if you use sockets.c)
 */
#define LWIP_POSIX_SOCKETS_IO_NAMES	0

#if 1
/**
 * CHECKSUM_CHECK_IP==1: Check checksums in software for incoming IP packets.
 */
#define CHECKSUM_CHECK_IP		0

/**
 * CHECKSUM_CHECK_UDP==1: Check checksums in software for incoming UDP packets.
 */
#define CHECKSUM_CHECK_UDP		0

/**
 * CHECKSUM_CHECK_TCP==1: Check checksums in software for incoming TCP packets.
 */
#define CHECKSUM_CHECK_TCP		0
#endif

/**
 * SO_REUSE==1: Enable SO_REUSEADDR option.
 */
#define SO_REUSE			1

/* DEBUG options */
#define LWIP_DEBUG		1
#define DHCP_DEBUG		LWIP_DBG_OFF
#define ETHARP_DEBUG		LWIP_DBG_OFF
#define TCPIP_DEBUG		LWIP_DBG_OFF
#define TCP_INPUT_DEBUG		LWIP_DBG_OFF
#define SYS_DEBUG		LWIP_DBG_ON
#define RAW_DEBUG		LWIP_DBG_OFF
#define MEM_DEBUG		LWIP_DBG_OFF
#define IP_DEBUG		LWIP_DBG_OFF
#define IP6_DEBUG		LWIP_DBG_OFF
#define INET_DEBUG		LWIP_DBG_OFF
#define NETIF_DEBUG		LWIP_DBG_ON
#define TIMERS_DEBUG		LWIP_DBG_OFF
#define SOCKETS_DEBUG		LWIP_DBG_OFF
#define PBUF_DEBUG		LWIP_DBG_OFF
#define API_LIB_DEBUG		LWIP_DBG_OFF

#define LWIP_TCPIP_CORE_LOCKING		1
#define LWIP_TCPIP_CORE_LOCKING_INPUT	1

//#define LWIP_TCPIP_THREAD_ALIVE()	kputs("TCPIP thread is alive!\n")
#endif
