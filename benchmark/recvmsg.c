/* SPDX-License-Identifier: MIT */

#include "helpers.h"
#include "liburing.h"
#include <assert.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/eventfd.h>
#include <unistd.h>
#include "../test/helpers.h"

struct event_ctx;
struct bench_ctx;

enum {
	SQES = 64,
	CQES = 2048,
	BUFFER_SIZE = 2000,
	NUM_BUFFERS = 4096, /* more than cqe at least */
};

struct param {
	struct basic_benchmark_parameter base;
	int count;
	bool multishot;
};

struct concurrent_ctx {
	struct bench_ctx *parent;
	int fds[2];
	struct msghdr msg;
	struct sockaddr_storage addr;
	struct iovec iov;
};

struct bench_ctx {
	struct basic_benchmark_ctx *basic;
	struct event_ctx *events;
	int nconcs;
	struct concurrent_ctx *concs;
};

void teardown(struct benchmark_ctx *ctx, void *user);

int init(struct benchmark_ctx *ctx, void **user)
{
	int i, ret;
	struct bench_ctx *b = (struct bench_ctx *)malloc(sizeof(*b));
	struct param *p = (struct param *) ctx->param;

	if (!b)
		return -ENOMEM;

	if (basic_benchmark_init_flags(ctx, (void **)&b->basic, IORING_SETUP_COOP_TASKRUN)) {
		free(b);
		return -1;
	}

	b->nconcs = p->count;
	b->concs = (struct concurrent_ctx *)malloc(sizeof(*b->concs) * b->nconcs);
	if (!b->concs)
		return -ENOMEM;

	ret = basic_benchmark_add_provided_buffers(
		b->basic,
		0,
		NUM_BUFFERS,
		BUFFER_SIZE);

	if (ret)
		return ret;

	for (i = 0; i < b->nconcs; i++) {
		struct concurrent_ctx *t = &b->concs[i];

		t->msg = (struct msghdr) {
			.msg_name = &t->addr,
			.msg_namelen = sizeof(t->addr),
			.msg_iovlen = 0,
		};
		t->parent = b;
		ret = t_create_socket_pair(t->fds, false);
		if (ret)
			return ret;
	}

	*user = b;
	return 0;
}

void teardown(struct benchmark_ctx *ctx, void *user)
{
	struct bench_ctx *b = user;
	basic_benchmark_teardown(ctx, b->basic);

	free(b->concs);
	free(b);
}

static int add_one_sqe(struct bench_ctx *b, struct param *p, int i) {
	struct io_uring_sqe *sqe = io_uring_get_sqe(&b->basic->ring);
	if (!sqe)
		return -1;
	io_uring_prep_recvmsg(sqe, b->concs[i].fds[1],
			&b->concs[i].msg,
			0);
	if (p->multishot)
		sqe->ioprio |= IORING_RECV_MULTISHOT;

	sqe->buf_group = 0;
	sqe->flags |= IOSQE_BUFFER_SELECT;
	sqe->user_data = i;
	return 0;
}

static int handle_one_cqe(struct bench_ctx *b, struct param *p, struct io_uring_cqe *cqe) {
	if (cqe->res < 0)
		return cqe->res;
	if (!(cqe->flags & IORING_CQE_F_BUFFER)) {
		fprintf(stderr, "no buff!\n");
		return -ENOBUFS;
	}
	basic_benchmark_add_buffer(
		b->basic,
		cqe->flags >> IORING_CQE_BUFFER_SHIFT,
		BUFFER_SIZE,
		0);
	if (!(cqe->flags & IORING_CQE_F_MORE))
		add_one_sqe(b, p, (int)cqe->user_data);
	return 0;
}

int run(struct benchmark_ctx *ctx, void *user)
{
	struct bench_ctx *b = user;
	struct param *p = (struct param *)ctx->param;
	struct io_uring_cqe *cqe[CQES];
	struct io_uring *ring = &b->basic->ring;
	int i, ret;
	uint64_t count = 0;
	unsigned int peeked;

	for (i = 0; i < p->count; i++) {
		ret = add_one_sqe(b, p, i);
		if(ret)
			return ret;
	}
	ret = io_uring_submit(&b->basic->ring);
	if (ret != p->count) {
		ret = -1;
		goto err;
	}

	BENCH_LOOP_START()
	{
		count = 0;

		for (i = 0; i < p->count; i++) {
			struct concurrent_ctx *t = b->concs + i;
			do {
				ret = send(t->fds[0], &t, sizeof(t), 0);
			} while  (ret == -1 && errno == EINTR);
		}

		ret = io_uring_wait_cqe(ring, &cqe[0]);

		if (ret)
			return ret;
		ret = handle_one_cqe(b, p, cqe[0]);
		if (ret)
			return ret;
		io_uring_cq_advance(ring, 1);

		peeked = io_uring_peek_batch_cqe(ring, &cqe[0], CQES);
		for (i = 0; i < peeked; i++) {
			ret = handle_one_cqe(b, p, cqe[i]);
			if (ret)
				return ret;
		}

		count = 1 + peeked;
		io_uring_cq_advance(ring, peeked);

		ret = io_uring_submit(&b->basic->ring);
		if (ret < 0)
			goto err;
	}
	BENCH_LOOP_END(ctx, count);
	return 0;
err:
	return ret;
}

int main(int argc, char *argv[])
{
	struct param params[] = {
		{ .base = basic_benchmark_params("1 no-multi", SQES, CQES),
		  .count = 1,
		  .multishot = false
		},
		{ .base = basic_benchmark_params("1 multi", SQES, CQES),
		  .count = 1,
		  .multishot = true
		},
		{ .base = basic_benchmark_params("4 no-multi", SQES, CQES),
		  .count = 4,
		  .multishot = false
		},
		{ .base = basic_benchmark_params("4 multi", SQES, CQES),
		  .count = 4,
		  .multishot = true
		},
		{}
	};

	struct benchmark_opts opts = parse_benchmark_opts(argc, argv);
	run_benchmark(&opts, "recvmsg", init, run, teardown, &params[0].base.base, sizeof(params[0]));
	return 0;
}
