/* SPDX-License-Identifier: MIT */
/*
 * Description: run various nop tests
 *
 */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#include "liburing.h"

static int seq;

static int test_single_nop(struct io_uring *ring)
{
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	int ret;

	sqe = io_uring_get_sqe(ring);
	if (!sqe) {
		fprintf(stderr, "get sqe failed\n");
		goto err;
	}

	io_uring_prep_nop(sqe);
	sqe->user_data = ++seq;

	ret = io_uring_submit(ring);
	if (ret <= 0) {
		fprintf(stderr, "sqe submit failed: %d\n", ret);
		goto err;
	}

	ret = io_uring_wait_cqe(ring, &cqe);
	if (ret < 0) {
		fprintf(stderr, "wait completion %d\n", ret);
		goto err;
	}
	if (!cqe->user_data) {
		fprintf(stderr, "Unexpected 0 user_data\n");
		goto err;
	}
	io_uring_cqe_seen(ring, cqe);
	return 0;
err:
	return 1;
}

static int test_barrier_nop(struct io_uring *ring)
{
	struct io_uring_cqe *cqe;
	struct io_uring_sqe *sqe;
	int ret, i;

	for (i = 0; i < 8; i++) {
		sqe = io_uring_get_sqe(ring);
		if (!sqe) {
			fprintf(stderr, "get sqe failed\n");
			goto err;
		}

		io_uring_prep_nop(sqe);
		if (i == 4)
			sqe->flags = IOSQE_IO_DRAIN;
		sqe->user_data = ++seq;
	}

	ret = io_uring_submit(ring);
	if (ret < 0) {
		fprintf(stderr, "sqe submit failed: %d\n", ret);
		goto err;
	} else if (ret < 8) {
		fprintf(stderr, "Submitted only %d\n", ret);
		goto err;
	}

	for (i = 0; i < 8; i++) {
		ret = io_uring_wait_cqe(ring, &cqe);
		if (ret < 0) {
			fprintf(stderr, "wait completion %d\n", ret);
			goto err;
		}
		if (!cqe->user_data) {
			fprintf(stderr, "Unexpected 0 user_data\n");
			goto err;
		}
		io_uring_cqe_seen(ring, cqe);
	}

	return 0;
err:
	return 1;
}

static int test_p(struct io_uring_params *p)
{
	struct io_uring ring;
	int ret;

	ret = io_uring_queue_init_params(8, &ring, p);
	if (ret) {
		fprintf(stderr, "ring setup failed: %d\n", ret);
		return 1;
	}

	ret = test_single_nop(&ring);
	if (ret) {
		fprintf(stderr, "test_single_nop failed\n");
		goto err;
	}

	ret = test_barrier_nop(&ring);
	if (ret) {
		fprintf(stderr, "test_barrier_nop failed\n");
		goto err;
	}

	io_uring_queue_exit(&ring);
	return 0;
err:
	io_uring_queue_exit(&ring);
	return ret;
}

static int test_normal_ring(void)
{
	struct io_uring_params p = { };

	return test_p(&p);
}

static int test_big_ring(void)
{
	struct io_uring_params p = { };

	p.flags = IORING_SETUP_SQE128;
	return test_p(&p);
}


int main(int argc, char *argv[])
{
	int ret;

	if (argc > 1)
		return 0;

	ret = test_normal_ring();
	if (ret) {
		fprintf(stderr, "Normal ring test failed\n");
		return ret;
	}

	ret = test_big_ring();
	if (ret) {
		fprintf(stderr, "Big ring test failed\n");
		return ret;
	}

	return 0;
}
