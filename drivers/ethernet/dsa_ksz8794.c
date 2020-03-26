/*
 * Copyright (c) 2020 DENX Software Engineering GmbH
 *               Lukasz Majewski <lukma@denx.de>
 * SPDX-License-Identifier: Apache-2.0
 */

#define DT_DRV_COMPAT microchip_ksz8794

#include <logging/log.h>
LOG_MODULE_REGISTER(dsa, CONFIG_ETHERNET_LOG_LEVEL);

#include <device.h>
#include <kernel.h>
#include <errno.h>
#include <sys/util.h>
#include <drivers/spi.h>
#include <net/ethernet.h>
#include <linker/sections.h>

#include "dsa_ksz8794.h"

static struct dsa_ksz8794_spi phy_spi;

static void dsa_ksz8794_write_reg(struct dsa_ksz8794_spi *sdev,
				  uint16_t reg_addr, uint8_t value)
{
	uint8_t buf[3];

	const struct spi_buf tx_buf = {
		.buf = buf,
		.len = 3
	};
	const struct spi_buf_set tx = {
		.buffers = &tx_buf,
		.count = 1
	};

	buf[0] = KSZ8794_SPI_CMD_WR | ((reg_addr >> 7) & 0x1F);
	buf[1] = (reg_addr << 1) & 0xFE;
	buf[2] = value;

	spi_write(sdev->spi, &sdev->spi_cfg, &tx);
}

static void dsa_ksz8794_read_reg(struct dsa_ksz8794_spi *sdev,
				 uint16_t reg_addr, uint8_t *value)
{
	uint8_t buf[3];

	const struct spi_buf tx_buf = {
		.buf = buf,
		.len = 3
	};
	const struct spi_buf_set tx = {
		.buffers = &tx_buf,
		.count = 1
	};
	struct spi_buf rx_buf = {
		.buf = buf,
		.len = 3
	};

	const struct spi_buf_set rx = {
		.buffers = &rx_buf,
		.count = 1
	};

	buf[0] = KSZ8794_SPI_CMD_RD | ((reg_addr >> 7) & 0x1F);
	buf[1] = (reg_addr << 1) & 0xFE;
	buf[2] = 0x0;

	if (!spi_transceive(sdev->spi, &sdev->spi_cfg, &tx, &rx)) {
		*value = buf[2];
	} else {
		LOG_DBG("Failure while reading register 0x%04x", reg_addr);
		*value = 0U;
	}
}

static bool dsa_ksz8794_port_link_status(struct dsa_ksz8794_spi *sdev,
					 uint8_t port)
{
	uint8_t tmp;

	if (port < KSZ8794_PORT1 || port > KSZ8794_PORT3) {
		return false;
	}

	dsa_ksz8794_read_reg(sdev, KSZ8794_STAT2_PORTn(port), &tmp);

	return tmp & KSZ8794_STAT2_LINK_GOOD;
}

static bool dsa_ksz8794_link_status(struct dsa_ksz8794_spi *sdev)
{
	bool ret = false;
	uint8_t i;

	for (i = KSZ8794_PORT1; i <= KSZ8794_PORT3; i++) {
		if (dsa_ksz8794_port_link_status(sdev, i)) {
			LOG_INF("Port: %d link UP!", i);
			ret |= true;
		}
	}

	return ret;
}

static void dsa_ksz8794_soft_reset(struct dsa_ksz8794_spi *sdev)
{
	/* reset switch */
	dsa_ksz8794_write_reg(sdev, KSZ8794_PD_MGMT_CTRL1,
			      KSZ8794_PWR_MGNT_MODE_SOFT_DOWN);
	k_busy_wait(1000);
	dsa_ksz8794_write_reg(sdev, KSZ8794_PD_MGMT_CTRL1, 0);
}

static int dsa_ksz8794_spi_setup(struct dsa_ksz8794_spi *sdev)
{
	uint16_t timeout = 100;
	uint8_t val[2], tmp;

	/* SPI config */
	sdev->spi_cfg.operation =
#if DT_INST_PROP(0, spi_cpol)
		SPI_MODE_CPOL |
#endif
#if DT_INST_PROP(0, spi_cpha)
		SPI_MODE_CPHA |
#endif
		SPI_WORD_SET(8);

	sdev->spi_cfg.frequency = DT_INST_PROP(0, spi_max_frequency);
	sdev->spi_cfg.slave = DT_INST_REG_ADDR(0);
	sdev->spi_cfg.cs = NULL;
	sdev->spi =	device_get_binding(DT_INST_BUS_LABEL(0));
	if (!sdev->spi) {
		return -EINVAL;
	}

	/*
	 * Wait for SPI of KSZ8794 being fully operational - up to 10 ms
	 */
	for (timeout = 100, tmp = 0;
	     tmp != KSZ8794_CHIP_ID0_ID_DEFAULT && timeout > 0; timeout--) {
		dsa_ksz8794_read_reg(sdev, KSZ8794_CHIP_ID0, &tmp);
		k_busy_wait(100);
	}

	if (timeout == 0) {
		LOG_ERR("KSZ8794: No SPI communication!");
		return -ENODEV;
	}

	dsa_ksz8794_read_reg(sdev, KSZ8794_CHIP_ID0, &val[0]);
	dsa_ksz8794_read_reg(sdev, KSZ8794_CHIP_ID1, &val[1]);

	LOG_DBG("KSZ8794: ID0: 0x%x ID1: 0x%x timeout: %d", val[1], val[0],
		timeout);

	return 0;
}

static int dsa_ksz8794_write_static_mac_table(struct dsa_ksz8794_spi *sdev,
					      uint16_t entry_addr, uint8_t *p)
{
	/*
	 * According to KSZ8794 manual - write to static mac address table
	 * requires write to indirect registers:
	 * Write register 0x71 (113)
	 * ....
	 * Write register 0x78 (120)
	 *
	 * Then:
	 * Write to Register 110 with 0x00 (write static table selected)
	 * Write to Register 111 with 0x0x (trigger the write operation, to
	 * table entry x)
	 */
	dsa_ksz8794_write_reg(sdev, KSZ8794_REG_IND_DATA_7, p[7]);
	dsa_ksz8794_write_reg(sdev, KSZ8794_REG_IND_DATA_6, p[6]);
	dsa_ksz8794_write_reg(sdev, KSZ8794_REG_IND_DATA_5, p[5]);
	dsa_ksz8794_write_reg(sdev, KSZ8794_REG_IND_DATA_4, p[4]);
	dsa_ksz8794_write_reg(sdev, KSZ8794_REG_IND_DATA_3, p[3]);
	dsa_ksz8794_write_reg(sdev, KSZ8794_REG_IND_DATA_2, p[2]);
	dsa_ksz8794_write_reg(sdev, KSZ8794_REG_IND_DATA_1, p[1]);
	dsa_ksz8794_write_reg(sdev, KSZ8794_REG_IND_DATA_0, p[0]);

	dsa_ksz8794_write_reg(sdev, KSZ8794_REG_IND_CTRL_0, 0x00);
	dsa_ksz8794_write_reg(sdev, KSZ8794_REG_IND_CTRL_1, entry_addr);

	return 0;
}

static int dsa_ksz8794_set_static_mac_table(struct dsa_ksz8794_spi *sdev,
					    const uint8_t *mac, uint8_t fw_port,
					    uint16_t entry_idx)
{
	/*
	 * The data in uint8_t buf[] buffer is stored in the little endian
	 * format, as it eases programming proper KSZ8794 registers.
	 */
	uint8_t buf[8];

	buf[7] = 0;
	/* Prepare entry for static MAC address table */
	buf[5] = mac[0];
	buf[4] = mac[1];
	buf[3] = mac[2];
	buf[2] = mac[3];
	buf[1] = mac[4];
	buf[0] = mac[5];

	buf[6] = fw_port;
	buf[6] |= KSZ8794_STATIC_MAC_TABLE_VALID;
	buf[6] |= KSZ8794_STATIC_MAC_TABLE_OVERRIDE;

	dsa_ksz8794_write_static_mac_table(sdev, entry_idx, buf);

	return 0;
}

static int dsa_ksz8794_read_static_mac_table(struct dsa_ksz8794_spi *sdev,
					      uint16_t entry_addr, uint8_t *p)
{
	/*
	 * According to KSZ8794 manual - read from static mac address table
	 * requires reads from indirect registers:
	 *
	 * Write to Register 110 with 0x10 (read static table selected)
	 * Write to Register 111 with 0x0x (trigger the read operation, to
	 * table entry x)
	 *
	 * Then:
	 * Write register 0x71 (113)
	 * ....
	 * Write register 0x78 (120)
	 *
	 */

	dsa_ksz8794_write_reg(sdev, KSZ8794_REG_IND_CTRL_0, 0x10);
	dsa_ksz8794_write_reg(sdev, KSZ8794_REG_IND_CTRL_1, entry_addr);

	dsa_ksz8794_read_reg(sdev, KSZ8794_REG_IND_DATA_7, &p[7]);
	dsa_ksz8794_read_reg(sdev, KSZ8794_REG_IND_DATA_6, &p[6]);
	dsa_ksz8794_read_reg(sdev, KSZ8794_REG_IND_DATA_5, &p[5]);
	dsa_ksz8794_read_reg(sdev, KSZ8794_REG_IND_DATA_4, &p[4]);
	dsa_ksz8794_read_reg(sdev, KSZ8794_REG_IND_DATA_3, &p[3]);
	dsa_ksz8794_read_reg(sdev, KSZ8794_REG_IND_DATA_2, &p[2]);
	dsa_ksz8794_read_reg(sdev, KSZ8794_REG_IND_DATA_1, &p[1]);
	dsa_ksz8794_read_reg(sdev, KSZ8794_REG_IND_DATA_0, &p[0]);

	return 0;
}

static int dsa_ksz8794_get_static_mac_table(struct dsa_ksz8794_spi *sdev,
					    uint8_t *buf, uint16_t entry_idx)
{
	return dsa_ksz8794_read_static_mac_table(sdev, entry_idx, buf);
}

static int dsa_ksz8794_switch_setup(struct dsa_ksz8794_spi *sdev)
{
	uint8_t tmp, i;

	/*
	 * Loop through ports - The same setup when tail tagging is enabled or
	 * disabled.
	 */
	for (i = KSZ8794_PORT1; i <= KSZ8794_PORT3; i++) {
		/* Enable transmission, reception and switch address learning */
		dsa_ksz8794_read_reg(sdev, KSZ8794_CTRL2_PORTn(i), &tmp);
		tmp |= KSZ8794_CTRL2_TRANSMIT_EN;
		tmp |= KSZ8794_CTRL2_RECEIVE_EN;
		tmp &= ~KSZ8794_CTRL2_LEARNING_DIS;
		dsa_ksz8794_write_reg(sdev, KSZ8794_CTRL2_PORTn(i), tmp);
	}

#if defined(CONFIG_DSA_KSZ8794_TAIL_TAGGING)
	/* Enable tail tag feature */
	dsa_ksz8794_read_reg(sdev, KSZ8794_GLOBAL_CTRL10, &tmp);
	tmp |= KSZ8794_GLOBAL_CTRL10_TAIL_TAG_EN;
	dsa_ksz8794_write_reg(sdev, KSZ8794_GLOBAL_CTRL10, tmp);
#else
	/* Disable tail tag feature */
	dsa_ksz8794_read_reg(sdev, KSZ8794_GLOBAL_CTRL10, &tmp);
	tmp &= ~KSZ8794_GLOBAL_CTRL10_TAIL_TAG_EN;
	dsa_ksz8794_write_reg(sdev, KSZ8794_GLOBAL_CTRL10, tmp);
#endif

	dsa_ksz8794_read_reg(sdev, KSZ8794_PORT4_IF_CTRL6, &tmp);
	LOG_DBG("KSZ8794: CONTROL6: 0x%x port4", tmp);

	dsa_ksz8794_read_reg(sdev, KSZ8794_PORT4_CTRL2, &tmp);
	LOG_DBG("KSZ8794: CONTROL2: 0x%x port4", tmp);

	dsa_ksz8794_read_reg(sdev, KSZ8794_GLOBAL_CTRL2, &tmp);
	tmp |= KSZ8794_GLOBAL_CTRL2_LEG_MAX_PKT_SIZ_CHK_DIS;
	dsa_ksz8794_write_reg(sdev, KSZ8794_GLOBAL_CTRL2, tmp);

	return 0;
}

/* Low level initialization code for DSA PHY */
int dsa_hw_init(struct device *dev)
{
	struct dsa_ksz8794_spi *swspi = &phy_spi;

	/* Time needed for KSZ8794 to completely power up (100ms) */
	k_busy_wait(100000);

	/* Configure SPI */
	dsa_ksz8794_spi_setup(swspi);

	/* Soft reset */
	dsa_ksz8794_soft_reset(swspi);

	/* Setup KSZ8794 */
	dsa_ksz8794_switch_setup(swspi);

	/* Read ports status */
	dsa_ksz8794_link_status(swspi);

	swspi->is_init = true;

	return 0;
}

static void dsa_delayed_work(struct k_work *item)
{
	struct dsa_context *context =
		CONTAINER_OF(item, struct dsa_context, dsa_work);
	bool link_state;
	uint8_t i;

	for (i = KSZ8794_PORT1; i <= KSZ8794_PORT3; i++) {
		link_state = dsa_ksz8794_port_link_status(&phy_spi, i);
		if (link_state && !context->link_up[i]) {
			LOG_INF("DSA port: %d link UP!", i);
			net_eth_carrier_on(context->iface_slave[i]);
		} else if (!link_state && context->link_up[i]) {
			LOG_INF("DSA port: %d link DOWN!", i);
			net_eth_carrier_off(context->iface_slave[i]);
		}
		context->link_up[i] = link_state;
	}

	k_delayed_work_submit(&context->dsa_work, DSA_STATUS_PERIOD_MS);
}

/*
 * Info regarding ports shall be parsed from DTS - as it is done in Linux
 * and moved to ./subsys/net/l2/ethernet/dsa/dsa.c
 */
int dsa_port_init(struct device *dev)
{
	struct dsa_context *context = dev->data;
	struct dsa_ksz8794_spi *swspi = &phy_spi;

	if (swspi->is_init) {
		return 0;
	}

	dsa_hw_init(NULL);
	k_delayed_work_init(&context->dsa_work, dsa_delayed_work);
	k_delayed_work_submit(&context->dsa_work, DSA_STATUS_PERIOD_MS);

	return 0;
}

/* Generic implementation of writing value to DSA register */
int dsa_write_reg(uint16_t reg_addr, uint8_t value)
{
	struct dsa_ksz8794_spi *swspi = &phy_spi;

	if (!swspi->is_init) {
		return -ENODEV;
	}

	dsa_ksz8794_write_reg(swspi, reg_addr, value);
	return 0;
}

/* Generic implementation of reading value from DSA register */
int dsa_read_reg(uint16_t reg_addr, uint8_t *value)
{
	struct dsa_ksz8794_spi *swspi = &phy_spi;

	if (!swspi->is_init) {
		return -ENODEV;
	}

	dsa_ksz8794_read_reg(swspi, reg_addr, value);
	return 0;
}

int dsa_set_mac_table_entry(const uint8_t *mac, uint8_t fw_port,
			    uint16_t tbl_entry_idx, uint16_t flags)
{
	struct dsa_ksz8794_spi *swspi = &phy_spi;

	if (!swspi->is_init) {
		return -ENODEV;
	}

	if (flags != 0) {
		return -EINVAL;
	}

	dsa_ksz8794_set_static_mac_table(swspi, mac, fw_port, tbl_entry_idx);

	return 0;
}

int dsa_get_mac_table_entry(uint8_t *buf, uint16_t tbl_entry_idx)
{
	struct dsa_ksz8794_spi *swspi = &phy_spi;

	if (!swspi->is_init) {
		return -ENODEV;
	}

	dsa_ksz8794_get_static_mac_table(swspi, buf, tbl_entry_idx);

	return 0;
}

#if defined(CONFIG_DSA_KSZ8794_TAIL_TAGGING)
#define DSA_KSZ8795_TAIL_TAG_OVERRIDE	BIT(6)
#define DSA_KSZ8795_TAIL_TAG_LOOKUP	BIT(7)

#define DSA_KSZ8794_EGRESS_TAG_LEN 1
#define DSA_KSZ8794_INGRESS_TAG_LEN 1

#define DSA_MIN_L2_FRAME_SIZE 64
#define DSA_L2_FCS_SIZE 4

struct net_pkt *dsa_xmit_pkt(struct net_if *iface, struct net_pkt *pkt)
{
	struct ethernet_context *ctx = net_if_l2_data(iface);
	struct net_eth_hdr *hdr = NET_ETH_HDR(pkt);
	struct net_linkaddr lladst;
	uint8_t port_idx, *dbuf;
	struct net_buf *buf;
	size_t len, pad = 0;

	lladst.len = sizeof(hdr->dst.addr);
	lladst.addr = &hdr->dst.addr[0];

	len = net_pkt_get_len(pkt);
	/*
	 * For KSZ8794 one needs to 'pad' the L2 frame to its minimal size
	 * (64B) before appending TAIL TAG and FCS
	 */
	if (len < (DSA_MIN_L2_FRAME_SIZE - DSA_L2_FCS_SIZE)) {
		/* Calculate number of bytes needed for padding */
		pad = DSA_MIN_L2_FRAME_SIZE - DSA_L2_FCS_SIZE - len;
	}

	buf = net_buf_alloc_len(net_buf_pool_get(pkt->buffer->pool_id),
				pad + DSA_KSZ8794_INGRESS_TAG_LEN, K_NO_WAIT);
	if (!buf) {
		LOG_ERR("DSA cannot allocate new data buffer");
		return NULL;
	}

	/*
	 * Get the pointer to struct's net_buf_simple data and zero out the
	 * padding and tag byte placeholder
	 */
	dbuf = net_buf_simple_tail(&(buf->b));
	memset(dbuf, 0x0, pad + DSA_KSZ8794_INGRESS_TAG_LEN);

	/*
	 * For master port (eth0) set the bit 7 to use look-up table to pass
	 * packet to correct interface (bits [0..6] _are_ ignored).
	 *
	 * For slave ports (lan1..3) just set the tag properly:
	 * bit 0 -> eth1, bit 1 -> eth2. bit 2 -> eth3
	 * It may be also necessary to set bit 6 to "anyhow send packets to
	 * specified port in Bits[3:0]". This may be needed for RSTP
	 * implementation (when the switch port is disabled, but shall handle
	 * LLDP packets).
	 */
	if (DSA_IS_PORT_MASTER(iface)) {
		port_idx = DSA_KSZ8795_TAIL_TAG_LOOKUP;
	} else {
		port_idx = (1 << (ctx->dsa_port_idx - 1));
	}

	NET_DBG("TT - port: 0x%x[%p] LEN: %d 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x",
		port_idx, iface, len, lladst.addr[0], lladst.addr[1],
		lladst.addr[2], lladst.addr[3], lladst.addr[4], lladst.addr[5]);

	/* The tail tag shall be placed after the padding (if present) */
	dbuf[pad] = port_idx;

	/* Set proper len member for the actual struct net_buf_simple */
	net_buf_add(buf, pad + DSA_KSZ8794_INGRESS_TAG_LEN);

	/* Append struct net_buf to packet data */
	net_buf_frag_add(pkt->buffer, buf);

	return pkt;
}

struct net_if *dsa_get_iface(struct net_if *iface, struct net_pkt *pkt)
{
	struct ethernet_context *ctx;
	struct net_if *iface_sw;
	size_t plen;
	uint8_t pnum;

	if (!(net_eth_get_hw_capabilities(iface) &
	      (ETHERNET_DSA_SLAVE_PORT | ETHERNET_DSA_MASTER_PORT))) {
		return iface;
	}

	net_pkt_cursor_init(pkt);
	plen = net_pkt_get_len(pkt);

	net_pkt_skip(pkt, plen - DSA_KSZ8794_EGRESS_TAG_LEN);
	net_pkt_read_u8(pkt, &pnum);

	net_pkt_update_length(pkt, plen - DSA_KSZ8794_EGRESS_TAG_LEN);

	/*
	 * NOTE:
	 * The below approach is only for ip_k66f board as we do know
	 * that eth0 is on position (index) 1, then we do have lan1 with
	 * index 2, lan2 with 3 and lan3 with 4.
	 *
	 * This is caused by eth interfaces placing order by linker and
	 * may vary on other boards, wthere are for example two eth
	 * interfaces available.
	 */
	iface_sw = net_if_get_by_index(pnum + 2);

	ctx = net_if_l2_data(iface);
	NET_DBG("TT - plen: %d pnum: %d pos: 0x%p dsa_port_idx: %d",
		plen - DSA_KSZ8794_EGRESS_TAG_LEN, pnum,
		net_pkt_cursor_get_pos(pkt), ctx->dsa_port_idx);

	return iface_sw;
}
#endif

void dsa_iface_init(struct net_if *iface)
{
	struct dsa_slave_config *cfg = (struct dsa_slave_config *)
		net_if_get_device(iface)->config;
	struct ethernet_context *ctx = net_if_l2_data(iface);
	struct device *dm, *dev = net_if_get_device(iface);
	struct dsa_context *context = dev->data;
	static uint8_t i = KSZ8794_PORT1;

	/* Find master port for ksz8794 switch */
	if (context->iface_master == NULL) {
		dm = device_get_binding(DT_INST_PROP_BY_PHANDLE(0,
								dsa_master_port,
								label));
		context->iface_master = net_if_lookup_by_dev(dm);
		if (context->iface_master == NULL) {
			LOG_INF("DSA: Master iface NOT found!");
		}
	}

	if (context->iface_slave[i] == NULL) {
		context->iface_slave[i] = iface;
		net_if_set_link_addr(iface, cfg->mac_addr,
				     sizeof(cfg->mac_addr),
				     NET_LINK_ETHERNET);
		ctx->dsa_port_idx = i;
	}

	i++;
	net_if_flag_set(iface, NET_IF_NO_AUTO_START);
}

static enum ethernet_hw_caps dsa_port_get_capabilities(struct device *dev)
{
	ARG_UNUSED(dev);

	return ETHERNET_DSA_SLAVE_PORT | ETHERNET_LINK_10BASE_T |
		ETHERNET_LINK_100BASE_T;
}

const struct ethernet_api dsa_api_funcs = {
	.iface_api.init		= dsa_iface_init,
	.get_capabilities	= dsa_port_get_capabilities,
	.send                   = dsa_tx,
};

static struct dsa_context dsa_0_context = {
	.num_slave_ports = DT_INST_PROP(0, dsa_slave_ports),
	.sw_read = dsa_read_reg,
	.sw_write = dsa_write_reg,
};

DT_INST_FOREACH_CHILD(0, NET_SLAVE_DEVICE_INIT_INSTANCE)
