/* SPDX-License-Identifier: MIT */

#include "helpers.h"
#include "liburing.h"
#include <stdio.h>
#include <poll.h>
#include <unistd.h>
#include <stdatomic.h>
#include <pthread.h>
#include <assert.h>
#include <sys/eventfd.h>

#define NSQE 128
#define NCQE (NSQE*4)

struct ctx {
	struct basic_benchmark_ctx *u;
	int fds[2];
	int eventfd;
	atomic_int done;
	pthread_t thread;
};

enum mode {
	UNKNOWN = 0,
	POLL = 1,
	POLL_MULTI,
	READ
};

struct param {
	struct basic_benchmark_parameter base;
	enum mode mode;
	bool thread;
	bool block;
	bool no_reg;
	bool eventfd;
};


static void teardown(struct benchmark_ctx *bctx, void *user)
{
	struct param *p = (struct param *) bctx->param;
	struct ctx *ctx = (struct ctx *) user;

	ctx->done = true;
	basic_benchmark_teardown(bctx, ctx->u);
	if (p->thread) {
		pthread_join(ctx->thread, NULL);
	}
	close(ctx->fds[0]);
	close(ctx->fds[1]);
	close(ctx->eventfd);
	free(ctx);
}

void *thread_run(void *user)
{
	struct ctx *ctx = user;
	struct pollfd p = {
		.fd = ctx->fds[0],
		.events = POLLIN,
	};
	while(!ctx->done) {
		poll(&p, 1, 0);
	}
	return NULL;
}

static int init(struct benchmark_ctx *bctx, void **user)
{
	int ret;
	struct param *p = (struct param *) bctx->param;
	struct ctx *ctx = (struct ctx *) malloc(sizeof(ctx));
	*user = ctx;
	assert(p->mode != UNKNOWN);

	if (!ctx)
		return -1;

	ret = basic_benchmark_init_flags(bctx, (void**)&ctx->u,
					IORING_SETUP_SINGLE_ISSUER |
					IORING_SETUP_DEFER_TASKRUN);
	if (ret)
		return ret;

	ret = pipe2(ctx->fds, !p->block ? O_NONBLOCK : 0);
	if (ret)
		return ret;

	ctx->eventfd = eventfd(1, 0);
	if (ctx->eventfd < 0)
		return -1;

	ret = io_uring_register_files(&ctx->u->ring, ctx->fds, 1);
	if (ret)
		return ret;

	if (p->eventfd) {
		ret = io_uring_register_eventfd(&ctx->u->ring, ctx->eventfd);
		if (ret)
			return ret;
	}

	ctx->done = false;
	if (p->thread) {
		if (pthread_create(&ctx->thread, NULL, thread_run, ctx))
			return -1;
	}
	return 0;
}

static int run(struct benchmark_ctx *ctx, void *user)
{
	struct ctx *c = user;
	struct basic_benchmark_ctx *u = c->u;
	uint32_t const sqe_length = basic_benchmark_sqe_length(ctx);
	uint32_t const count = sqe_length;
	struct param *p = (struct param *) ctx->param;
	struct io_uring_cqe *cqe[count];
	struct io_uring_sqe *sqe;
	struct io_uring_sqe sqe_base;
	char buff[count];
	int i, ret, to_write = 0, used_fd;
	unsigned saved;
	unsigned flags;

	if (p->no_reg) {
		used_fd = c->fds[0];
		flags = 0;
	} else {
		used_fd = 0;
		flags = IOSQE_FIXED_FILE;
	}

	switch(p->mode) {
	case UNKNOWN: return -1;
	case READ:
		io_uring_prep_read(&sqe_base, used_fd, &buff, 1, 0);
		to_write = count;
		break;
	case POLL:
		io_uring_prep_poll_add(&sqe_base, used_fd, POLLIN);
		to_write = 1;
		break;
	case POLL_MULTI:
		io_uring_prep_poll_multishot(&sqe_base, used_fd, POLLIN);
		to_write = 1;
		break;
	};
	sqe_base.flags |= flags;

	if (p->mode == POLL_MULTI) {
		for (i = 0; i < count; i++) {
			sqe = io_uring_get_sqe(&u->ring);
			assert(sqe);
			*sqe = sqe_base;
			sqe->user_data = i;
		}
		io_uring_submit(&u->ring);
	}

	BENCH_LOOP_SLOW_START()
	{
		if (p->mode != POLL_MULTI) {
			for (i = 0; i < count; i++) {
				sqe = io_uring_get_sqe(&u->ring);
				assert(sqe);
				*sqe = sqe_base;
			}
			io_uring_submit(&u->ring);
		}

		if(to_write != write(c->fds[1], &buff, to_write)) {
			return -1;
		}
		ret = io_uring_wait_cqes(&u->ring, &cqe[0], count, NULL, NULL);
		if (ret)
			return ret;
		saved = io_uring_cq_ready(&u->ring);
		if (saved != count) {
			fprintf(stderr, "bad ready %u %u %d\n", saved, io_uring_cq_ready(&u->ring), count);
			exit(-1);
		}
		assert(io_uring_cq_ready(&u->ring) == count);
		switch (p->mode) {
		case UNKNOWN: return -1;
		case READ:
			break;
		case POLL_MULTI: {
				int c2 = 0;
				unsigned head;
				io_uring_for_each_cqe(&u->ring, head, cqe[0]) {
					if (!(cqe[0]->flags & IORING_CQE_F_MORE)) {
						sqe = io_uring_get_sqe(&u->ring);
						*sqe = sqe_base;
						sqe->user_data = cqe[0]->user_data;
						c2++;
					}
				}
				if (c2) {
					ret = io_uring_submit(&u->ring);
					assert(ret == c2);
				}
			}
			/* fallthrough */
		case POLL:
			ret = read(c->fds[0], &buff, to_write);
			assert(ret == to_write);
			break;
		};
		io_uring_cq_advance(&u->ring, count);
	}
	BENCH_LOOP_SLOW_END(ctx, count);
	return 0;
}

int main(int argc, char *argv[])
{
	struct param params[] = {
		(struct param) {
			.base = basic_benchmark_params("poll", NSQE, NCQE),
			.mode = POLL,
		},
		(struct param) {
			.base = basic_benchmark_params("poll_multi eventfd", NSQE, NCQE),
			.mode = POLL_MULTI,
			.eventfd = true,
		},
		(struct param) {
			.base = basic_benchmark_params("poll no_reg", NSQE, NCQE),
			.mode = POLL,
			.no_reg = true,
		},
		(struct param) {
			.base = basic_benchmark_params("poll_multi no_reg", NSQE, NCQE),
			.mode = POLL_MULTI,
			.no_reg = true,
		},
		(struct param) {
			.base = basic_benchmark_params("poll thread", NSQE, NCQE),
			.thread = true,
			.mode = POLL,
		},
		(struct param) {
			.base = basic_benchmark_params("read thread", NSQE, NCQE),
			.thread = true,
			.mode = READ,
		},
		(struct param) {
			.base = basic_benchmark_params("read", NSQE, NCQE),
			.mode = READ,
		},
		(struct param) {
			.base = basic_benchmark_params("read no_reg", NSQE, NCQE),
			.no_reg = true,
			.mode = READ,
		},
		(struct param) {
			.base = basic_benchmark_params("read block", NSQE, NCQE),
			.block = true,
			.mode = READ,
		},
		{}
	};
	struct benchmark_opts opts = parse_benchmark_opts(argc, argv);
	run_benchmark(&opts, "reg", init, run,
		      teardown,
		      (struct benchmark_parameter *)params, sizeof(params[0]));
	return 0;
}
