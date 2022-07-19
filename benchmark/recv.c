/* SPDX-License-Identifier: MIT */

#include "helpers.h"
#include "liburing.h"
#include <assert.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/eventfd.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <poll.h>
#include "../test/helpers.h"

struct bench_ctx;
struct concurrent_ctx;

enum {
	SQES = 256,
	CQES = 2048,
	BUFFER_SIZE = 2000,
	NUM_BUFFERS = 4096, /* more than cqe at least */
};

struct param {
	struct basic_benchmark_parameter base;
	int count;
};

struct recv_thread {
	pthread_t thread;
	atomic_int done;
	int fds[2];
};

struct concurrent_ctx {
	struct bench_ctx *parent;
	int fds[2];
	struct recv_thread thread;
};

struct bench_ctx {
	struct basic_benchmark_ctx *basic;
	struct event_ctx *events;
	int nconcs;
	struct concurrent_ctx *concs;
};

struct epoll_bench_ctx {
	int efd;
	int nconcs;
	struct recv_thread *concs;
};


void *thread_run(void *user)
{
	char buff[2048];
	struct recv_thread *t = user;
	int ret;
	struct pollfd pfd = {
		.fd = t->fds[1],
		.events = POLLIN
	};

	while(!t->done) {
		ret = poll(&pfd, 1, 100);
		if (ret <= 0 || !(pfd.revents & POLLIN))
			continue;
		ret = recv(t->fds[1], buff, sizeof(buff), 0);
		if (ret >= 0)
			send(t->fds[1], buff, ret, 0);
	}
	return NULL;
}

int init_thread(struct recv_thread *recv, int fds[2]) {
	memcpy(recv->fds, fds, sizeof(recv->fds));
	recv->done = false;
	if (pthread_create(&recv->thread, NULL, &thread_run, recv))
		return -1;
	pthread_setname_np(recv->thread, "bg thread");
	return 0;
}

void stop_thread(struct recv_thread *recv) {
	close(recv->fds[0]);
	close(recv->fds[1]);
	recv->done = 1;
	pthread_join(recv->thread, NULL);
}

void teardown(struct benchmark_ctx *ctx, void *user);

int init(struct benchmark_ctx *ctx, void **user)
{
	int i, ret;
	struct bench_ctx *b = (struct bench_ctx *)malloc(sizeof(*b));
	struct param *p = (struct param *) ctx->param;
	int files[p->count];

	if (!b)
		return -ENOMEM;

	if (basic_benchmark_init_flags(ctx, (void **)&b->basic, IORING_SETUP_COOP_TASKRUN)) {
		free(b);
		return -1;
	}

	ret = io_uring_register_ring_fd(&b->basic->ring);
	if (ret < 0) {
		return ret;
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
		t->parent = b;
		ret = t_create_socket_pair(t->fds, false);
		if (ret)
			return ret;
		ret = init_thread(&t->thread, t->fds);
		if (ret)
			return ret;
		files[i] = t->fds[0];
	}

	ret = io_uring_register_files(&b->basic->ring, files, b->nconcs);
	if (ret) {
		return ret;
	}

	*user = b;
	return 0;
}

void teardown(struct benchmark_ctx *ctx, void *user)
{
	struct bench_ctx *b = user;
	int i;

	basic_benchmark_teardown(ctx, b->basic);

	for (i = 0; i < b->nconcs; i++) {
		stop_thread(&b->concs[i].thread);
	}
	free(b->concs);
	free(b);
}

static int add_one_sqe(struct bench_ctx *b, struct param *p, int i) {
	struct io_uring_sqe *sqe = io_uring_get_sqe(&b->basic->ring);
	if (!sqe)
		return -1;
	io_uring_prep_recv(sqe, i, NULL, 0, 0);
	sqe->ioprio |= IORING_RECV_MULTISHOT;

	sqe->buf_group = 0;
	sqe->flags |= IOSQE_BUFFER_SELECT;
	sqe->flags |= IOSQE_FIXED_FILE;
	sqe->user_data = i;
	return 0;
}

static int handle_one_cqe(struct bench_ctx *b, struct param *p, struct io_uring_cqe *cqe) {
	int ret;
	int idx = (int)cqe->user_data;

	if (cqe->res < 0)
		return cqe->res;
	if (!(cqe->flags & IORING_CQE_F_BUFFER)) {
		return -ENOBUFS;
	}
	basic_benchmark_add_buffer(
		b->basic,
		cqe->flags >> IORING_CQE_BUFFER_SHIFT,
		BUFFER_SIZE,
		0);
	if (!(cqe->flags & IORING_CQE_F_MORE))
		add_one_sqe(b, p, idx);

	do {
		ret = send(b->concs[idx].fds[0], &b, sizeof(b), 0);
	} while  (ret == -1 && errno == EINTR);

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

	for (i = 0; i < p->count; i++) {
		struct concurrent_ctx *t = b->concs + i;
		do {
			ret = send(t->fds[0], &t, sizeof(t), 0);
		} while  (ret == -1 && errno == EINTR);
	}

	BENCH_LOOP_START()
	{
		count = 0;

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


int init_epoll(struct benchmark_ctx *ctx, void **user)
{
	int i, ret;
	struct epoll_bench_ctx *b = (struct epoll_bench_ctx *)malloc(sizeof(*b));
	struct param *p = (struct param *) ctx->param;

	if (!b)
		return -ENOMEM;

	b->nconcs = p->count;
	b->concs = (struct recv_thread *)malloc(sizeof(*b->concs) * b->nconcs);
	if (!b->concs)
		return -ENOMEM;
	b->efd = epoll_create(1);
	if (b->efd < 0)
		return -errno;

	for (i = 0; i < b->nconcs; i++) {
		int fds[2];
		struct epoll_event ev;

		ret = t_create_socket_pair(fds, false);
		if (ret)
			return ret;

		ev = (struct epoll_event) {
			.events = EPOLLIN,
			.data = (union epoll_data) {
				.u32 = i
			}
		};
		if (epoll_ctl(b->efd, EPOLL_CTL_ADD, fds[0], &ev))
			return -errno;
		ret = init_thread(b->concs + i, fds);
		if (ret)
			return ret;
	}

	*user = b;
	return 0;
}

void teardown_epoll(struct benchmark_ctx *ctx, void *user)
{
	struct epoll_bench_ctx *b = user;
	int i;

	for (i = 0; i < b->nconcs; i++) {
		stop_thread(&b->concs[i]);
	}
	free(b->concs);
	close(b->efd);
	free(b);
}

int run_epoll(struct benchmark_ctx *ctx, void *user)
{
	struct epoll_bench_ctx *b = user;
	struct param *p = (struct param *)ctx->param;
	struct epoll_event events[CQES];
	int i, ret = 0;
	char buff[2048];
	uint64_t count = 0;

	for (i = 0; i < p->count; i++) {
		struct recv_thread *t = b->concs + i;
		do {
			ret = send(t->fds[0], &t, sizeof(t), 0);
		} while  (ret == -1 && errno == EINTR);
	}

	BENCH_LOOP_START()
	{
		count = 0;

		while (count < b->nconcs) {
			int eret;

			eret = epoll_wait(b->efd, events, ARRAY_SIZE(events), 0);
			if (eret < 0)
				return -errno;
			for (i = 0; i < eret; i++) {
				struct recv_thread *t;
				int sz;

				if (!(events[i].events & EPOLLIN))
					goto err;

				t = b->concs + events[i].data.u32;
				do {
					sz = recv(t->fds[0], buff, sizeof(buff), 0);
				} while  (sz == -1 && errno == EINTR);

				do {
					ret = send(t->fds[0], buff, sz, 0);
				} while  (ret == -1 && errno == EINTR);

				count++;
			}
		}
	}
	BENCH_LOOP_END(ctx, count);
	return 0;
err:
	return ret;
}

int main(int argc, char *argv[])
{
	struct param params[] = {
		{ .base = basic_benchmark_params("1", SQES, CQES),
		  .count = 1,
		},
		{ .base = basic_benchmark_params("4", SQES, CQES),
		  .count = 4 ,
		},
		{ .base = basic_benchmark_params("16", SQES, CQES),
		  .count = 16 ,
		},
		{ .base = basic_benchmark_params("128", SQES, CQES),
		  .count = 128,
		},
		{}
	};

	struct benchmark_opts opts = parse_benchmark_opts(argc, argv);
	run_benchmark(&opts, "recv", init, run, teardown, &params[0].base.base, sizeof(params[0]));
	run_benchmark(&opts, "recv_epoll", init_epoll, run_epoll, teardown_epoll, &params[0].base.base, sizeof(params[0]));

	return 0;
}
