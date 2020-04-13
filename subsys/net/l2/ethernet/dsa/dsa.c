/** @file
 * @brief DSA related functions
 */

/*
 * Copyright (c) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <logging/log.h>
LOG_MODULE_REGISTER(net_dsa, CONFIG_NET_DSA_LOG_LEVEL);

#include <errno.h>
#include <stdlib.h>

#include <net/net_core.h>
#include <net/ethernet.h>
#include <net/net_mgmt.h>
#include <net/dsa.h>

/*
 * RECEIVE HANDLING CODE - ingress (ETH -> DSA slave ports)
 */

static int dsa_check_iface(struct net_if *iface)
{
	if (net_if_l2(iface) != &NET_L2_GET_NAME(ETHERNET)) {
		return -ENOENT;
	}

	if (!((net_eth_get_hw_capabilities(iface) & ETHERNET_DSA_MASTER_PORT) ||
	    (net_eth_get_hw_capabilities(iface) & ETHERNET_DSA_SLAVE_PORT))) {
		return -ESRCH;
	}

	return 0;
}

int dsa_register_recv_callback(struct net_if *iface, net_dsa_recv_cb_t cb)
{
	struct ethernet_context *ctx;
	int ret;

	ret = dsa_check_iface(iface);
	if (ret < 0) {
		return ret;
	}

	if (cb) {
		ctx = net_if_l2_data(iface);
		ctx->cb = cb;
	}

	return 0;
}

int net_dsa_recv(struct net_if *iface, struct net_pkt *pkt)
{
	struct ethernet_context *ctx;
	int ret;

	ret = dsa_check_iface(iface);
	if (ret < 0) {
		return ret;
	}

	ctx = net_if_l2_data(iface);
	if (ctx->cb) {
		return ctx->cb(iface, pkt);
	}

	return 0;
}

int dsa_enable_port(struct net_if *iface, uint8_t port)
{
	return 0;
}

__weak int dsa_set_mac_table_entry(const uint8_t *mac, uint8_t fw_port,
				   uint16_t tbl_entry_idx, uint16_t flags)
{
	return 0;
}

__weak int dsa_get_mac_table_entry(uint8_t *buf, uint16_t tbl_entry_idx)
{
	return 0;
}

__weak struct net_pkt *dsa_xmit_pkt(struct net_if *iface, struct net_pkt *pkt)
{
	return pkt;
}

__weak struct net_if *dsa_get_iface(struct net_if *iface, struct net_pkt *pkt)
{
	struct net_eth_hdr *hdr = NET_ETH_HDR(pkt);
	struct net_linkaddr lladst;
	struct net_if *iface_sw;

	if (!(net_eth_get_hw_capabilities(iface) &
	      (ETHERNET_DSA_SLAVE_PORT | ETHERNET_DSA_MASTER_PORT))) {
		return iface;
	}

	lladst.len = sizeof(hdr->dst.addr);
	lladst.addr = &hdr->dst.addr[0];

	iface_sw = net_if_get_by_link_addr(&lladst);
	if (iface_sw) {
		return iface_sw;
	}

	return iface;
}

struct net_if *dsa_recv_set_iface(struct net_if *iface, struct net_pkt **pkt)
{
	struct net_if *iface_sw = dsa_get_iface(iface, *pkt);

	/*
	 * Optional code to change the destination interface with some
	 * custom callback (to e.g. filter/switch packets based on MAC).
	 *
	 * The callback shall be only present (and used) for lan1..3, but
	 * not for the master interface, which shall support all other
	 * protocols - i.e. UDP. ICMP, TCP.
	 */
	if (net_dsa_recv(iface_sw, *pkt)) {
		return iface_sw;
	}

	return iface;
}

/*
 * TRANSMISSION HANDLING CODE egress (DSA slave ports -> ETH)
 */
int eth_tx(struct device *dev, struct net_pkt *pkt);
int dsa_tx(struct device *dev, struct net_pkt *pkt)
{
	struct dsa_context *context;
	struct net_if *iface_master, *iface;

	iface = net_if_lookup_by_dev(dev);
	if (iface == NULL) {
		NET_ERR("DSA: No iface interface!");
		return -ENODEV;
	}

	if (DSA_IS_PORT_MASTER(iface)) {
		return eth_tx(dev, dsa_xmit_pkt(iface, pkt));
	}

	context = dev->data;
	iface_master = context->iface_master;

	if (iface_master == NULL) {
		NET_ERR("DSA: No master interface!");
		return -ENODEV;
	}

	/* Adjust packet for DSA routing and send it via master interface */
	return eth_tx(net_if_get_device(iface_master),
		      dsa_xmit_pkt(iface, pkt));
}
