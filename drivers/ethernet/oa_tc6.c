/*
 * Copyright (c) 2023 DENX Software Engineering GmbH
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "oa_tc6.h"

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(oa_tc6, CONFIG_ETHERNET_LOG_LEVEL);

NET_BUF_POOL_FIXED_DEFINE(oa_tc6_pool_tx, CONFIG_OA_TC6_TX_POOL_SIZE, 64, \
                          OA_TC6_HDR_SIZE, NULL);
int oa_tc6_reg_read(struct oa_tc6 *tc6, const uint32_t reg, uint32_t *val)
{
	uint8_t buf[OA_TC6_HDR_SIZE + 12] = { 0 };
	struct spi_buf tx_buf = { .buf = buf, .len = sizeof(buf) };
	const struct spi_buf_set tx = {	.buffers = &tx_buf, .count = 1 };
	struct spi_buf rx_buf = { .buf = buf, .len = sizeof(buf) };
	const struct spi_buf_set rx = {	.buffers = &rx_buf, .count = 1 };
	uint32_t rv, rvn, hdr_bkp, *hdr = (uint32_t *) &buf[0];
	int ret = 0;

	/*
	 * Buffers are allocated for protected (larger) case (by 4 bytes).
	 * When non-protected case - we need to decrase them
	 */
	if (!tc6->protected) {
		tx_buf.len -= sizeof(rvn);
		rx_buf.len -= sizeof(rvn);
	}

	*hdr = FIELD_PREP(OA_CTRL_HDR_DNC, 0) |
		FIELD_PREP(OA_CTRL_HDR_WNR, 0) |
		FIELD_PREP(OA_CTRL_HDR_AID, 0) |
		FIELD_PREP(OA_CTRL_HDR_MMS, reg >> 16) |
		FIELD_PREP(OA_CTRL_HDR_ADDR, reg) |
		FIELD_PREP(OA_CTRL_HDR_LEN, 0); /* To read single register len = 0 */
	*hdr |= FIELD_PREP(OA_CTRL_HDR_P, oa_tc6_get_parity(*hdr));
	hdr_bkp = *hdr;
	*hdr = sys_cpu_to_be32(*hdr);

	ret = spi_transceive_dt(tc6->spi, &tx, &rx);
	if (ret < 0) {
		return ret;
	}

	/* Check if echoed control command header is correct */
	rv = sys_be32_to_cpu(*(uint32_t *)&buf[4]);
	if (hdr_bkp != rv) {
		LOG_ERR("Header transmission error!");
		return -1;
	}

	rv = sys_be32_to_cpu(*(uint32_t *)&buf[8]);

	/* In protected mode read data is followed by its compliment value */
	if (tc6->protected) {
		rvn = sys_be32_to_cpu(*(uint32_t *)&buf[12]);
		if (rv != ~rvn) {
			LOG_ERR("Protected mode transmission error!");
			return -1;
		}
	}

	*val = rv;

	return ret;
}

int oa_tc6_reg_write(struct oa_tc6 *tc6, const uint32_t reg, uint32_t val)
{
	uint8_t buf_tx[OA_TC6_HDR_SIZE + 12] = { 0 };
	uint8_t buf_rx[OA_TC6_HDR_SIZE + 12] = { 0 };
	struct spi_buf tx_buf = { .buf = buf_tx, .len = sizeof(buf_tx) };
	const struct spi_buf_set tx = {	.buffers = &tx_buf, .count = 1 };
	struct spi_buf rx_buf = { .buf = buf_rx, .len = sizeof(buf_rx) };
	const struct spi_buf_set rx = {	.buffers = &rx_buf, .count = 1	};
	uint32_t rv, rvn, hdr_bkp, *hdr = (uint32_t *) &buf_tx[0];
	int ret;

	/*
	 * Buffers are allocated for protected (larger) case (by 4 bytes).
	 * When non-protected case - we need to decrase them
	 */
	if (!tc6->protected) {
		tx_buf.len -= sizeof(rvn);
		rx_buf.len -= sizeof(rvn);
	}

	*hdr = FIELD_PREP(OA_CTRL_HDR_DNC, 0) |
		FIELD_PREP(OA_CTRL_HDR_WNR, 1) |
		FIELD_PREP(OA_CTRL_HDR_AID, 0) |
		FIELD_PREP(OA_CTRL_HDR_MMS, reg >> 16) |
		FIELD_PREP(OA_CTRL_HDR_ADDR, reg) |
		FIELD_PREP(OA_CTRL_HDR_LEN, 0); /* To read single register len = 0 */
	*hdr |= FIELD_PREP(OA_CTRL_HDR_P, oa_tc6_get_parity(*hdr));
	hdr_bkp = *hdr;
	*hdr = sys_cpu_to_be32(*hdr);

	*(uint32_t *)&buf_tx[4] = sys_cpu_to_be32(val);
	if (tc6->protected) {
		*(uint32_t *)&buf_tx[8] = sys_be32_to_cpu(~val);
	}

	ret = spi_transceive_dt(tc6->spi, &tx, &rx);
	if (ret < 0) {
		return ret;
	}

	/* Check if echoed control command header is correct */
	rv = sys_be32_to_cpu(*(uint32_t *)&buf_rx[4]);
	if (hdr_bkp != rv) {
		LOG_ERR("Header transmission error!");
		return -1;
	}

	/* Check if echoed value is correct */
	rv = sys_be32_to_cpu(*(uint32_t *)&buf_rx[8]);
	if (val != rv) {
		LOG_ERR("Header transmission error!");
		return -1;
	}

	/*
	 * In protected mode check if read value is followed by its
	 * compliment value
	 */
	if (tc6->protected) {
		rvn = sys_be32_to_cpu(*(uint32_t *)&buf_rx[12]);
		if (val != ~rvn) {
			LOG_ERR("Protected mode transmission error!");
			return -1;
		}
	}

	return ret;
}

int oa_tc6_set_protected_ctrl(struct oa_tc6 *tc6, bool prote)
{
	uint32_t val;
	int ret;

	ret = oa_tc6_reg_read(tc6, OA_CONFIG0, &val);
	if (ret < 0) {
		return ret;
	}

	if (prote) {
		val |= OA_CONFIG0_PROTE;
	} else {
		val &= ~OA_CONFIG0_PROTE;
	}

	ret = oa_tc6_reg_write(tc6, OA_CONFIG0, val);
	if (ret < 0) {
		return ret;
	}

	tc6->protected = prote;
	return 0;
}

static void oa_tc6_rxtx(struct oa_tc6 *tc6)
{
	struct net_buf *tx;
	uint32_t hdr, ftr;
	int ret;

	while (true) {
		tx = net_buf_get(&tc6->tx_fifo, K_FOREVER);
		memcpy(&hdr, tx->user_data, tx->user_data_size);

		ret = oa_tc6_chunk_spi_transfer(tc6, NULL, tx->data, hdr, &ftr);
		if (ret < 0) {
			LOG_ERR("OA RXTX: SPI transmission error!");
		}

		net_buf_unref(tx);
	}
}

int oa_tc6_init(struct oa_tc6 *tc6)
{
	k_fifo_init(&tc6->rx_fifo);
	k_fifo_init(&tc6->tx_fifo);

	/* Start RX/TX thread */
	tc6->tid_rxtx =
		k_thread_create(&tc6->rxtx, tc6->rxtx_stack,
				CONFIG_OA_TC6_RXTX_THREAD_STACK_SIZE,
				(k_thread_entry_t)oa_tc6_rxtx,
				(void *)tc6, NULL, NULL,
				K_PRIO_COOP(CONFIG_OA_TC6_RXTX_THREAD_PRIO),
				0, K_NO_WAIT);
	k_thread_name_set(tc6->tid_rxtx, "oa_tc6_rxtx");

	return 0;
}

int oa_tc6_send_chunks(struct oa_tc6 *tc6, struct net_pkt *pkt)
{
	uint16_t len = net_pkt_get_len(pkt);
	struct net_buf *buf;
	uint8_t chunks, i;
	uint32_t hdr;
	int ret;

	chunks = (len / tc6->cps) + 1;

	/* Check if LAN865x has any free internal buffer space */
	if (chunks > tc6->txc) {
		return -EIO;
	}

	/* Transform struct net_pkt content into chunks */
	for (i = 1; i <= chunks; i++, len -= tc6->cps) {
		buf = net_buf_alloc(&oa_tc6_pool_tx, OA_TC6_BUF_ALLOC_TIMEOUT);
		if (!buf) {
			LOG_ERR("OA RX: Can't allocate RT buffer fordata!");
			return -ENOMEM;
		}

		hdr = FIELD_PREP(OA_DATA_HDR_DNC, 1) |
			FIELD_PREP(OA_DATA_HDR_DV, 1) |
			FIELD_PREP(OA_DATA_HDR_NORX, 1) |
			FIELD_PREP(OA_DATA_HDR_SWO, 0);

		if (i == 1) {
			hdr |=	FIELD_PREP(OA_DATA_HDR_SV, 1);
		}

		if (i == chunks) {
			hdr |= FIELD_PREP(OA_DATA_HDR_EBO, len - 1) |
				FIELD_PREP(OA_DATA_HDR_EV, 1);
		}

		hdr |= FIELD_PREP(OA_DATA_HDR_P, oa_tc6_get_parity(hdr));

		buf->len = len > tc6->cps ? tc6->cps : len;
		/*
		 * One needs to use net_pkt_read() as net stack can form packet
		 * from many "frags" with different sizes (and hence one cannot
		 * use this data as an underlaying continous buffer).
		 */
		ret = net_pkt_read(pkt, buf->data, buf->len);
		if (ret < 0) {
			return ret;
		}

		/* The header word is passed with buffer */
		memcpy(buf->user_data, &hdr, buf->user_data_size);

		net_buf_put(&tc6->tx_fifo, buf);
	}

	return 0;
}

static void oa_tc6_update_status(struct oa_tc6 *tc6, uint32_t ftr)
{
	tc6->exst = FIELD_GET(OA_DATA_FTR_EXST, ftr);
	tc6->sync = FIELD_GET(OA_DATA_FTR_SYNC, ftr);
	tc6->rca = FIELD_GET(OA_DATA_FTR_RCA, ftr);
	tc6->txc = FIELD_GET(OA_DATA_FTR_TXC, ftr);
}

int oa_tc6_update_buf_info(struct oa_tc6 *tc6)
{
	uint32_t val;
	int ret;

	ret = oa_tc6_reg_read(tc6, OA_BUFSTS, &val);
	if (ret < 0) {
		return ret;
	}

	tc6->rca = FIELD_GET(OA_BUFSTS_RCA, val);
	tc6->txc = FIELD_GET(OA_BUFSTS_TXC, val);

	return 0;
}

int oa_tc6_chunk_spi_transfer(struct oa_tc6 *tc6, uint8_t *buf_rx, uint8_t *buf_tx,
				     uint32_t hdr, uint32_t *ftr)
{
	struct spi_buf tx_buf[2];
	struct spi_buf rx_buf[2];
	struct spi_buf_set tx;
	struct spi_buf_set rx;
	int ret;

	hdr = sys_cpu_to_be32(hdr);
	tx_buf[0].buf = &hdr;
	tx_buf[0].len = sizeof(hdr);

	tx_buf[1].buf = buf_tx;
	tx_buf[1].len = tc6->cps;

	tx.buffers = tx_buf;
	tx.count = ARRAY_SIZE(tx_buf);

	rx_buf[0].buf = buf_rx;
	rx_buf[0].len = tc6->cps;

	rx_buf[1].buf = ftr;
	rx_buf[1].len = sizeof(*ftr);

	rx.buffers = rx_buf;
	rx.count = ARRAY_SIZE(rx_buf);

	ret = spi_transceive_dt(tc6->spi, &tx, &rx);
	if (ret < 0) {
		return ret;
	}
	*ftr = sys_be32_to_cpu(*ftr);
	oa_tc6_update_status(tc6, *ftr);

	return 0;
}

int oa_tc6_read_status(struct oa_tc6 *tc6, uint32_t *ftr)
{
	uint32_t hdr;

	hdr = FIELD_PREP(OA_DATA_HDR_DNC, 1) |
		FIELD_PREP(OA_DATA_HDR_DV, 0) |
		FIELD_PREP(OA_DATA_HDR_NORX, 1);
	hdr |= FIELD_PREP(OA_DATA_HDR_P, oa_tc6_get_parity(hdr));

	return oa_tc6_chunk_spi_transfer(tc6, NULL, NULL, hdr, ftr);
}

int oa_tc6_read_chunks(struct oa_tc6 *tc6, struct net_pkt *pkt)
{
	struct net_buf *buf_rx = NULL;
	uint32_t hdr, ftr;
	uint8_t chunks;
	int ret;

	for (chunks = tc6->rca; chunks; chunks--) {
		buf_rx = net_pkt_get_frag(pkt, tc6->cps, OA_TC6_BUF_ALLOC_TIMEOUT);
		if (!buf_rx) {
			LOG_ERR("OA RX: Can't allocate RX buffer fordata!");
			return -ENOMEM;
		}

		hdr = FIELD_PREP(OA_DATA_HDR_DNC, 1);
		hdr |= FIELD_PREP(OA_DATA_HDR_P, oa_tc6_get_parity(hdr));

		ret = oa_tc6_chunk_spi_transfer(tc6, buf_rx->data, NULL, hdr, &ftr);
		if (ret < 0) {
			LOG_ERR("OA RX: transmission error: %d!", ret);
			goto unref_buf;
		}

		ret = -EIO;
		if (oa_tc6_get_parity(ftr)) {
			LOG_ERR("OA RX: Footer parity error!");
			goto unref_buf;
		}

		if (!FIELD_GET(OA_DATA_FTR_SYNC, ftr)) {
			LOG_ERR("OA RX: Configuration not SYNC'ed!");
			goto unref_buf;
		}

		if (!FIELD_GET(OA_DATA_FTR_DV, ftr)) {
			LOG_ERR("OA RX: Data chunk not valid, skip!");
			goto unref_buf;
		}

		if (FIELD_GET(OA_DATA_FTR_SV, ftr)) {
			/* Adjust beginning of the buffer with SWO */
			uint8_t swo = FIELD_GET(OA_DATA_FTR_SWO, ftr);

			if (swo) {
				net_buf_pull(buf_rx, sizeof(uint32_t) * swo);
			}
		}

		net_pkt_append_buffer(pkt, buf_rx);

		if (!FIELD_GET(OA_DATA_FTR_EV, ftr)) {
			buf_rx->len = tc6->cps;
		} else {
			/* Set final size of the buffer */
			uint8_t ebo = FIELD_GET(OA_DATA_FTR_EBO, ftr) + 1;

			buf_rx->len = ebo;
			/*
			 * Exit when complete packet is read and added to
			 * struct net_pkt
			 */
			break;
		}
	}

	return 0;

 unref_buf:
	net_buf_unref(buf_rx);
	return ret;
}
