/* SPDX-License-Identifier: MIT */

/* Benchmark to force a lot of task work, and different size task work batches.
 * If profiling it is best to avoid the background threads as they spin a lot.
 * for example
 * $ perf record -g -t $(pgrep tw.b) sleep 5
 */

#include "helpers.h"
#include "liburing.h"
#include <assert.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/eventfd.h>
#include <unistd.h>

#define OUTER_SHIFT 28
#define OUTER_MASK 3
#define INNER_MASK ~(OUTER_MASK << OUTER_SHIFT)

struct param {
	struct basic_benchmark_parameter base;
	bool coop;
	bool multithread;
	int batch;
};

struct event_ctx;
struct bench_ctx;
struct thread_ctx {
	pthread_t thread;
	struct bench_ctx *parent;
	int idx;
};

struct bench_ctx {
	struct basic_benchmark_ctx *basic;
	int n;
	struct event_ctx *events;
	atomic_int signal;
	atomic_int signal_done;
	int nthreads;
	struct thread_ctx *threads;
};

struct event_ctx {
	int fd;
	int io_uring_idx;
};

void *thread_run_all(void *user)
{
	struct thread_ctx *tc = user;
	struct bench_ctx *b = tc->parent;
	unsigned count = 0;
	int ret;
	int idx = 0;
	int i;
	int sig = 0;
	while (true) {
		uint64_t buff = 1;
		do {
			sig = atomic_exchange(&b->signal, 0);
		} while (!sig);
		for (i = 0; i < sig; i++) {
			ret = write(b->events[idx].fd, &buff, 8);
			if (ret != 8)
				goto done;
			if (++idx == b->n)
				idx = 0;
		}
		b->signal_done = sig;
		count++;
	}
done:
	for (i = 0; i < b->n; i++) {
		close(b->events[i].fd);
	}
	return NULL;
}

void *thread_run_one(void *user)
{
	struct thread_ctx *tc = user;
	struct bench_ctx *b = tc->parent;
	unsigned count = 0;
	int ret;
	int sig;
	int last_outer = 0;
	int this_outer;

	while (true) {
		uint64_t buff = 1;
		do {
			sig = atomic_load(&b->signal);
			this_outer = (sig >> OUTER_SHIFT) & OUTER_MASK;
		} while (this_outer == last_outer || (sig & INNER_MASK) < tc->idx);
		last_outer = this_outer;

		ret = write(b->events[tc->idx].fd, &buff, 8);
		if (ret != 8)
			goto done;
		atomic_fetch_add(&b->signal_done, 1);
		count++;
	}
done:
	close(b->events[tc->idx].fd);
	return NULL;
}

int init_thread(struct event_ctx *ctx)
{
	ctx->fd = eventfd(0, O_NONBLOCK);
	return ctx->fd >= 0 ? 0 : errno;
}

void close_event(struct event_ctx *ctx)
{
	close(ctx->fd);
}

void teardown(struct benchmark_ctx *ctx, void *user);

int init(struct benchmark_ctx *ctx, void **user)
{
	int i, ret;
	int *files;
	int flags = 0;
	struct bench_ctx *b = (struct bench_ctx *)malloc(sizeof(*b));
	struct param *p = (struct param *)ctx->param;

	if (!b)
		return -ENOMEM;
	if (p->coop)
		flags |= IORING_SETUP_COOP_TASKRUN;
	if (basic_benchmark_init_flags(ctx, (void **)&b->basic, flags)) {
		free(b);
		return -1;
	}

	b->signal = 0;
	b->signal_done = 0;
	/* div 2 to make sure we dont overflow */
	b->n = basic_benchmark_cqe_length(ctx) / 2;
	b->events = (struct event_ctx *)malloc(sizeof(b->events[0]) * b->n);

	b->nthreads = p->multithread ? b->n : 1;
	b->threads = (struct thread_ctx *)malloc(sizeof(*b->threads) * b->nthreads);
	if (!b->threads)
		return -ENOMEM;

	memset(b->events, 0, sizeof(b->events[0]) * b->n);
	for (i = 0; i < b->n; i++)
		assert(!init_thread(b->events + i));

	files = (int *)malloc(sizeof(int) * b->n);
	for (i = 0; i < b->n; i++) {
		files[i] = b->events[i].fd;
		b->events[i].io_uring_idx = i;
	}
	ret = io_uring_register_files(&b->basic->ring, files, b->n);
	free(files);

	for (i = 0; i < b->nthreads; i++) {
		b->threads[i].parent = b;
		b->threads[i].idx = i;
		if (pthread_create(&b->threads[i].thread, NULL, p->multithread ? &thread_run_one : &thread_run_all, &b->threads[i]))
			return -1;
		pthread_setname_np(b->threads[i].thread, "bg thread");
	}

	if (ret) {
		teardown(ctx, b);
		return ret;
	}
	*user = b;
	return 0;
}

void teardown(struct benchmark_ctx *ctx, void *user)
{
	int i;
	struct bench_ctx *b = user;
	basic_benchmark_teardown(ctx, b->basic);
	for (i = 0; i < b->n; i++)
		close_event(&b->events[i]);
	/* make sure to change the outer bits */
	b->signal = (b->signal ^ (OUTER_MASK << OUTER_SHIFT)) + 16000;
	b->signal_done = b->signal;
	for (i = 0; i < b->nthreads; i++) {
		pthread_join(b->threads[i].thread, NULL);
	}
	free(b->threads);
	free(b);
}

static int process_cqe(struct io_uring *ring, int count)
{
	int ret;
	struct io_uring_cqe *cqe = NULL;
	while (count) {
		ret = io_uring_wait_cqe(ring, &cqe);
		if (ret)
			return ret;
		if (cqe->res < 0) {
			fprintf(stderr, "CQE bad res %d\n", cqe->res);
			return cqe->res;
		}
		count--;
		io_uring_cq_advance(ring, 1);
	}
	return 0;
}

int run(struct benchmark_ctx *ctx, void *user)
{
	struct bench_ctx *b = user;
	uint32_t const count = b->n;
	uint32_t const batch_size = ((struct param *)ctx->param)->batch;
	struct io_uring_sqe *sqe;
	uint64_t buff;
	int i, j, ret;
	int this_batch;
	int outer_counter = 0;

	BENCH_LOOP_START()
	{
		for (i = 0; i < count; i++) {
			sqe = io_uring_get_sqe(&b->basic->ring);
			if (!sqe)
				return -1;
			io_uring_prep_read(sqe, b->events[i].io_uring_idx,
					   &buff, 8, 0);
			sqe->flags |= IOSQE_FIXED_FILE;
			sqe->user_data = i;
		}
		/* submit the reads that will get task work */

		io_uring_submit(&b->basic->ring);
		j = count;
		atomic_store(&b->signal,  ((++outer_counter) & OUTER_MASK) << OUTER_SHIFT);
		while (j > 0) {
			/*
			 * for each batch it is important to try and do the same
			 * amount of work, just in different orders to encourage
			 * batching of task work.
			 */
			this_batch = j > batch_size ? batch_size : j;

			/* signal thread */
			atomic_fetch_add(&b->signal, this_batch);

			/* run some syscalls, maybe running task work */
			for (i = 0; i < this_batch; i++) {
				getpid();
			}
			j -= this_batch;
		}

		ret = process_cqe(&b->basic->ring, count);
		if (ret)
			goto err;
	}
	BENCH_LOOP_END(ctx, count);
	return 0;
err:
	return ret;
}

int main(int argc, char *argv[])
{
	/* CQE/SQE size is 2xcount per loop */
	struct param params[] = {
		{ .base = basic_benchmark_params("16 Batch 1", 32, 32),
		  .batch = 1
		},
		{ .base = basic_benchmark_params("16 Batch 16", 32, 32),
		  .batch = 16,
		},
		{ .base = basic_benchmark_params("16 Batch 1 COOP", 32, 32),
		  .batch = 1,
		  .coop = true,
		},
		{ .base = basic_benchmark_params("16 Batch 16 COOP", 32, 32),
		  .batch = 16,
		  .coop = true,
		},
		{ .base = basic_benchmark_params("32 Batch 1 COOP MULTITHREAD", 64, 64),
		  .batch = 1,
		  .coop = true,
		  .multithread = true,
		},
		{ .base = basic_benchmark_params("32 Batch 32 COOP MULTITHREAD", 64, 64),
		  .batch = 32,
		  .coop = true,
		  .multithread = true,
		},
		{}
	};
	struct benchmark_opts opts = parse_benchmark_opts(argc, argv);
	run_benchmark(&opts, "tw",
		      init, run, teardown,
		      (struct benchmark_parameter *)params, sizeof(params[0]));
	return 0;
}
