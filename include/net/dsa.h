/*
 * Copyright (c) 2020 DENX Software Engineering GmbH
 *               Lukasz Majewski <lukma@denx.de>
 * SPDX-License-Identifier: Apache-2.0
 */

/** @file
 * @brief DSA definitions and handlers
 */

#ifndef ZEPHYR_INCLUDE_NET_DSA_H_
#define ZEPHYR_INCLUDE_NET_DSA_H_

#include <device.h>
#include <net/net_if.h>

/**
 * @brief DSA definitions and helpers
 * @defgroup DSA - Distributed Switch Architecture definitions and helpers
 * @ingroup networking
 * @{
 */

#define NET_DSA_PORT_MAX_COUNT 8
#define DSA_STATUS_PERIOD_MS K_MSEC(1000)

/*
 * Size of the DSA TAG:
 * - KSZ8794 - 1 byte
 */
#if defined(CONFIG_DSA_KSZ8794) && defined(CONFIG_DSA_KSZ8794_TAIL_TAGGING)
#define _DSA_TAG_SIZE 1
#else
#define _DSA_TAG_SIZE 0
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief DSA function to adjust packet
 *
 * This is a function for adjusting packets passed from slave DSA interface to
 * master (e.g. implement tail tagging).
 *
 * @param iface Network interface
 * @param pkt Network packet
 *
 * Returns:
 *  - Pointer to (modified) net_pkt structure
 */
struct net_pkt *dsa_xmit_pkt(struct net_if *iface, struct net_pkt *pkt);

/**
 * @brief DSA generic transmit function
 *
 * This is a generic function for passing packets from slave DSA interface to
 * master.
 *
 * @param dev Device
 * @param pkt Network packet
 *
 * Returns:
 *  - 0 if ok (packet sent via master iface), < 0 if error
 */
int dsa_tx(struct device *dev, struct net_pkt *pkt);


/**
 * @brief DSA function to get proper interface
 *
 * This is a generic function for assigning proper slave interface after
 * receiving the packet on master.
 *
 * @param iface Network interface
 * @param pkt Network packet
 *
 * Returns:
 *  - Pointer to struct net_if
 */
struct net_if *dsa_get_iface(struct net_if *iface, struct net_pkt *pkt);

/**
 * @brief DSA (MGMT) Receive packet callback
 *
 * Callback gets called upon receiving packet. It is responsible for
 * freeing packet or indicating to the stack that it needs to free packet
 * by returning correct net_verdict.
 *
 * Returns:
 *  - NET_DROP, if packet was invalid, rejected or we want the stack to free it.
 *    In this case the core stack will free the packet.
 *  - NET_OK, if the packet was accepted, in this case the ownership of the
 *    net_pkt goes to callback and core network stack will forget it.
 */
typedef enum net_verdict (*net_dsa_recv_cb_t)(struct net_if *iface,
					      struct net_pkt *pkt);

/**
 * @brief Register DSA Rx callback functions
 *
 * @param iface Network interface
 * @param cb Receive callback function
 *
 * @return 0 if ok, < 0 if error
 */
int dsa_register_recv_callback(struct net_if *iface, net_dsa_recv_cb_t cb);

/**
 * @brief Parse DSA packet
 *
 * @param iface Network interface (master)
 * @param pkt Network packet
 *
 * @return Return 1 if packet needs to be altered in any way
 */
int net_dsa_recv(struct net_if *iface, struct net_pkt *pkt);

/**
 * @brief Set DSA interface to packet
 *
 * @param iface Network interface (master)
 * @param pkt Network packet
 *
 * @return Return the slave network interface
 */
struct net_if *dsa_recv_set_iface(struct net_if *iface, struct net_pkt **pkt);

/**
 * @brief Write value to DSA register
 */
int dsa_write_reg(uint16_t reg_addr, uint8_t value);

/**
 * @brief Read value from DSA register
 */
int dsa_read_reg(uint16_t reg_addr, uint8_t *value);

/**
 * @brief Enable DSA port
 *
 * @param iface Network interface (master)
 * @param port Port number to be enabled
 *
 * @return 0 if ok, < 0 if error
 */
int dsa_enable_port(struct net_if *iface, uint8_t port);

/**
 * @brief Set entry to DSA MAC address table
 *
 * @param mac The MAC address to be set in the table
 * @param fw_port Port number to forward packets
 * @param tbl_entry_idx The index of entry in the table
 * @param flags Flags to be set in the entry
 *
 * @return 0 if ok, < 0 if error
 */
int dsa_set_mac_table_entry(const uint8_t *mac, uint8_t fw_port,
			    uint16_t tbl_entry_idx, uint16_t flags);

/**
 * @brief Get DSA MAC address table entry
 *
 * @param buf The buffer for data read from the table
 * @param tbl_entry_idx The index of entry in the table
 *
 * @return 0 if ok, < 0 if error
 */
int dsa_get_mac_table_entry(uint8_t *buf, uint16_t tbl_entry_idx);

/**
 * @brief Structure to provide dsa context
 */

struct dsa_context {
	uint8_t num_slave_ports;
	struct k_delayed_work dsa_work;
	struct net_if *iface_slave[NET_DSA_PORT_MAX_COUNT];
	struct net_if *iface_master;
	bool link_up[NET_DSA_PORT_MAX_COUNT];

	int (*sw_read)(uint16_t reg_addr, uint8_t *value);
	int (*sw_write)(uint16_t reg_addr, uint8_t value);
};

#ifdef __cplusplus
}
#endif

/* DSA Macros */
#define DSA_IS_PORT_MASTER(iface) \
	(net_eth_get_hw_capabilities(iface) & ETHERNET_DSA_MASTER_PORT)

extern const struct ethernet_api dsa_api_funcs;
int dsa_port_init(struct device *dev);

/*
 * The order of NET_DEVICE_INIT_INSTANCE() placement IS important.
 *
 * To make the code simpler - the special care needs to be put on
 * the proper placement of eth0, lan1, lan2, lan3, etc - to avoid
 * the needs to search for proper interface when each packet is
 * received or sent.
 * The net_if.c has a very fast API to provide access to linked by
 * the linker struct net_if(s) via device or index. As it is already
 * available for use - let's use it.
 *
 * To do that one needs to check how linker places the interfaces.
 * To inspect:
 * objdump -dst ./zephyr/CMakeFiles/zephyr.dir/drivers/ethernet/eth_mcux.c.obj\
 * | grep "__net_if"
 * (The real problem is with eth0 and lanX order)
 *
 * If this approach is not enough for a simple system (like e.g. ip_k66f, one
 * can prepare dedicated linker script for the board to force the
 * order for complicated designs (like ones with eth0, eth1, and lanX).
 *
 * For simple cases it is just good enough.
 */

struct dsa_slave_config {
	uint8_t mac_addr[6];
};

#define NET_SLAVE_DEVICE_INIT_INSTANCE(slave)                              \
	const struct dsa_slave_config dsa_0_slave_##slave##_config = {     \
		.mac_addr = DT_PROP_OR(slave, local_mac_address, {0})      \
	};                                                                 \
	NET_DEVICE_INIT_INSTANCE(dsa_slave_port_##slave,                   \
	DT_LABEL(slave),                                                   \
	0,                                                                 \
	dsa_port_init,                                                     \
	ETH_MCUX_PM_FUNC,                                                  \
	&dsa_0_context,                                                    \
	&dsa_0_slave_##slave##_config,                                     \
	CONFIG_ETH_INIT_PRIORITY,                                          \
	&dsa_api_funcs,                                                    \
	ETHERNET_L2,                                                       \
	NET_L2_GET_CTX_TYPE(ETHERNET_L2),                                  \
	NET_ETH_MTU);

/**
 * @}
 */
#endif /* ZEPHYR_INCLUDE_NET_DSA_H_ */
