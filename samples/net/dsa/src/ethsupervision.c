/*
 * Copyright (c) 2020 Securiton
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <net/socket.h>
#include <net/net_core.h>
#include <net/net_l2.h>
#include <net/net_if.h>
#include <net/socket.h>
#include <net/ethernet.h>
#include <errno.h>

#include <logging/log.h>
#include "main.h"

// Loglevel of ethsupervision function
LOG_MODULE_REGISTER(ethsupervision, LOG_LEVEL_DBG);

/* in Securisafe 0x8267 is used */
#define PRIVATE_ETHER_TYPE 0x8267

#define ETH_DISCOVER_REVISION 1

struct eth_discover {
  uint8_t  cmd;                 /* COMMAND */
  uint8_t  revision;            /* protocol revision */
  uint16_t seq;                 /* sequence number */
  uint16_t cksum;               /* checksum */
  uint16_t src_port;            /* src port */
  uint16_t origin_port;         /* origin port */
  struct eth_addr origin_addr;   /* origin hardware address */
  uint8_t  padding[PACKET_LEN-16]; /* padding for 128 Byte data */
};
#define BUF_SIZ (sizeof(struct eth_discover) + sizeof (struct net_eth_hdr))

static uint16_t in_cksum(uint16_t *buf, int sz) {
	int nleft = sz;
	int sum = 0;
	uint16_t *w = buf;
	uint16_t ans = 0;

	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1) {
		*(unsigned char *) (&ans) = *(unsigned char *) w;
		sum += ans;
	}

	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	ans = ~sum;
	return ans;
}

int ethSupervision_send(struct net_if *iface, struct instance_data *pd,
			uint16_t seq, int src_port, int origin_port, int cmd,
			struct eth_addr* origin_addr)
{
	/* Send back data */
	int ret;
	char buffer[BUF_SIZ];
	struct sockaddr_ll dst;
	struct dsa_context *context;
	struct net_eth_hdr *eth_hdr = (struct net_eth_hdr *) buffer;
	struct eth_discover *eth_discover = (struct eth_discover*)
		&buffer[sizeof(struct net_eth_hdr)];

	dst.sll_ifindex = net_if_get_by_iface(iface);
	context = net_if_get_device(iface)->data;
	/* Construct the Ethernet header */
	memset(buffer, 0, BUF_SIZ);
	/* Ethernet header */
	/* take mac addr from master (HW) */
	memcpy(eth_hdr->src.addr, net_if_get_link_addr(ifaces.master)->addr,
	       ETH_ALEN);
	eth_hdr->dst.addr[0] = MCAST_DEST_MAC0;
	eth_hdr->dst.addr[1] = MCAST_DEST_MAC1;
	eth_hdr->dst.addr[2] = MCAST_DEST_MAC2;
	eth_hdr->dst.addr[3] = MCAST_DEST_MAC3;
	eth_hdr->dst.addr[4] = MCAST_DEST_MAC4;
	eth_hdr->dst.addr[5] = MCAST_DEST_MAC5;

	/* Ethertype field */
	eth_hdr->type = htons(PRIVATE_ETHER_TYPE);

	/* Discover Packet data */
	eth_discover->cmd = cmd;
	eth_discover->revision = ETH_DISCOVER_REVISION;
	eth_discover->seq                 = htons(seq);
	eth_discover->src_port            = htons(src_port);
	eth_discover->origin_port         = htons(origin_port);

	memcpy(eth_discover->origin_addr.addr, origin_addr, ETH_ALEN);

	eth_discover->cksum = in_cksum((uint16_t*)eth_discover,
				       sizeof(struct eth_discover));

	ret = sendto(pd->sock, buffer, sizeof(buffer), 0,
		     (const struct sockaddr *)&dst,
		     sizeof(struct sockaddr_ll));
	if (ret < 0) {
		LOG_ERR("Failed to send, errno %d", errno);
	}

	return 0;
}

int ethSupervision_recv(struct net_if *iface, struct instance_data *pd,
			uint16_t *seq, int *origin_port,
			struct eth_addr* origin_addr)
{
	struct net_eth_hdr *eth_hdr =
		(struct net_eth_hdr *) pd->recv_buffer;
	struct eth_discover *eth_discover =
		(struct eth_discover *)
		&pd->recv_buffer[sizeof(struct net_eth_hdr)];
	uint16_t cksum = 0;
	int received;

	/* Receive data */
	received = recv(pd->sock, pd->recv_buffer,
			sizeof(pd->recv_buffer), 0);
	if (received < 0) {
		LOG_ERR("RAW : recv error %d", errno);
		return -1;
	}

	if (received <
	    (int)sizeof(struct eth_discover) +
	    (int)sizeof(struct net_eth_hdr)) {
		LOG_ERR("[ERROR] too short packet %d bytes received\n",
			received);
		return -1;
	}

	cksum = eth_discover->cksum;
	eth_discover->cksum = 0;
	uint16_t cksum_recalc  = in_cksum((uint16_t*)eth_discover,
				       sizeof(struct eth_discover));
	if (cksum != cksum_recalc) {
		LOG_ERR("[ERROR] cksum missmatch 0x%04x / 0x%04x\n",
			cksum, cksum_recalc);
		return -1;
	}

	if (eth_discover->cmd == CMD_DISCOVER) {
		LOG_INF("rx discover on=%s seq=%3u origin=%d %02x:%02x:%02x:%02x:%02x:%02x",
			log_strdup(pd->if_name),
			ntohs(eth_discover->seq),
			ntohs(eth_discover->origin_port),
			eth_discover->origin_addr.addr[0],
			eth_discover->origin_addr.addr[1],
			eth_discover->origin_addr.addr[2],
			eth_discover->origin_addr.addr[3],
			eth_discover->origin_addr.addr[4],
			eth_discover->origin_addr.addr[5]);
		LOG_INF("src=%02x:%02x:%02x:%02x:%02x:%02x",
			eth_hdr->src.addr[0],
			eth_hdr->src.addr[1],
			eth_hdr->src.addr[2],
			eth_hdr->src.addr[3],
			eth_hdr->src.addr[4],
			eth_hdr->src.addr[5]);
		LOG_INF("dst=%02x:%02x:%02x:%02x:%02x:%02x",
			eth_hdr->dst.addr[0],
			eth_hdr->dst.addr[1],
			eth_hdr->dst.addr[2],
			eth_hdr->dst.addr[3],
			eth_hdr->dst.addr[4],
			eth_hdr->dst.addr[5]);
	}

	*seq = ntohs(eth_discover->seq);
	*origin_port = ntohs(eth_discover->origin_port);
	memcpy(origin_addr, eth_discover->origin_addr.addr,
	       sizeof(struct eth_addr) );

	return 0;
}

DSA_THREAD(1, ethSupervision_recv, ethSupervision_send)
DSA_THREAD(2, ethSupervision_recv, ethSupervision_send)
DSA_THREAD(3, ethSupervision_recv, ethSupervision_send)
