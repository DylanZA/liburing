/* SPDX-License-Identifier: MIT */

#include "helpers.h"
#include "liburing.h"
#include <stdio.h>
#include <sys/eventfd.h>
#include <poll.h>
#include <unistd.h>

enum Mode {
	NONE,
	DIRECT,
	EVENTFD
};

enum {
	NCQE = 1,
	NSQE = 1
};

struct ctx {
	struct basic_benchmark_ctx *u;
	int eventfd;
};

struct param {
	struct basic_benchmark_parameter base;
	enum Mode mode;
	bool async;
};


static void teardown(struct benchmark_ctx *bctx, void *user)
{
	struct ctx *ctx = (struct ctx *) user;
	basic_benchmark_teardown(bctx, ctx->u);

	if (ctx->eventfd > 0)
		close(ctx->eventfd);
}

static int init(struct benchmark_ctx *bctx, void **user)
{
	int ret;
	struct param *p = (struct param *) bctx->param;
	struct ctx *ctx = (struct ctx *) malloc(sizeof(ctx));
	*user = ctx;

	if (!ctx)
		return -1;

	ret = basic_benchmark_init(bctx, (void**)&ctx->u);
	if (ret)
		return ret;

	if (p->mode == EVENTFD) {
		ctx->eventfd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
		if (ctx->eventfd < 0)
			return -errno;
		if (p->async)
			ret = io_uring_register_eventfd_async(&ctx->u->ring, ctx->eventfd);
		else
			ret = io_uring_register_eventfd(&ctx->u->ring, ctx->eventfd);

		if (ret)
			return ret;
	} else {
		ctx->eventfd = -1;
	}

	return 0;
}

static int run(struct benchmark_ctx *ctx, void *user)
{
	struct ctx *c = user;
	struct basic_benchmark_ctx *u = c->u;
	uint32_t const sqe_length = basic_benchmark_sqe_length(ctx);
	uint32_t const count = basic_benchmark_cqe_length(ctx);
	struct param *p = (struct param *) ctx->param;
	struct io_uring_cqe *cqe[count];
	struct io_uring_sqe *sqe;
	uint32_t i;
	int ret;
	int waitfd = -1;
	char buff[8];
	int flags = p->async ? IOSQE_ASYNC : 0;

	switch(p->mode) {
	case NONE:
		waitfd = -1;
		break;
	case EVENTFD:
		waitfd = c->eventfd;
		break;
	case DIRECT:
		waitfd = u->ring.ring_fd;
		break;
	};
	struct pollfd pfd = {
		.fd = waitfd,
		.events = POLLIN
	};

	BENCH_LOOP_START()
	{
		int processed = 0;

		for (i = 0; i < count; i++) {
			sqe = io_uring_get_sqe(&u->ring);
			if (!sqe) {
				if (io_uring_submit(&u->ring) != sqe_length)
					return -1;
				sqe = io_uring_get_sqe(&u->ring);
				if (!sqe)
					return -1;
			}
			io_uring_prep_nop(sqe);
			sqe->flags |= flags;
		}

		/* proces count */
		while (processed < count) {
			switch(p->mode) {
			case NONE:
				io_uring_submit_and_wait(&u->ring, count - processed);
				break;
			case DIRECT:
				io_uring_submit(&u->ring);
				poll(&pfd, 1, 0);
				break;
			case EVENTFD:
				io_uring_submit(&u->ring);
				poll(&pfd, 1, 0);
				read(c->eventfd, buff, 8);
				break;
			};

			ret = io_uring_peek_batch_cqe(&u->ring, &cqe[0], count);
			if (ret < 0)
				return ret;
			processed += ret;
			io_uring_cq_advance(&u->ring, ret);
		}
	}
	BENCH_LOOP_END(ctx, count);
	return 0;
}

int main(int argc, char *argv[])
{
	struct param params[] = {
		(struct param) {
			.base = basic_benchmark_params("none", NSQE, NCQE),
			.mode = NONE
		},
		(struct param) {
			.base = basic_benchmark_params("eventfd", NSQE, NCQE),
			.mode = EVENTFD
		},
		(struct param) {
			.base = basic_benchmark_params("direct", NSQE, NCQE),
			.mode = DIRECT
		},
		(struct param) {
			.base = basic_benchmark_params("none_async", NSQE, NCQE),
			.mode = NONE,
			.async = true,
		},
		(struct param) {
			.base = basic_benchmark_params("eventfd_async", NSQE, NCQE),
			.mode = EVENTFD,
			.async = true,
		},
		(struct param) {
			.base = basic_benchmark_params("direct_async", NSQE, NCQE),
			.mode = DIRECT,
			.async = true,
		},
		{}
	};
	struct benchmark_opts opts = parse_benchmark_opts(argc, argv);
	run_benchmark(&opts, "poll", init, run,
		      teardown,
		      (struct benchmark_parameter *)params, sizeof(params[0]));
	return 0;
}
