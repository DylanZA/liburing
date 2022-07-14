/* SPDX-License-Identifier: MIT */

#include "helpers.h"
#include "liburing.h"
#include <stdio.h>

static int run(struct benchmark_ctx *ctx, void *user,
	int (*process)(struct io_uring *, struct io_uring_cqe **, unsigned))
{
	struct basic_benchmark_ctx *u = user;
	uint32_t const sqe_length = basic_benchmark_sqe_length(ctx);
	uint32_t const count = basic_benchmark_cqe_length(ctx);
	struct io_uring_cqe *cqe[count];
	struct io_uring_sqe *sqe;
	uint32_t i;
	int ret;

	BENCH_LOOP_START()
	{
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
		}
		io_uring_submit_and_wait(&u->ring, count);
		ret = process(&u->ring, &cqe[0], count);
		if (ret)
			return ret;
	}
	BENCH_LOOP_END(ctx, count);
	return 0;
}

static int process_old(struct io_uring *ring, struct io_uring_cqe **cqe,
		unsigned count)
{
	unsigned i;

	if (count != io_uring_peek_batch_cqe(ring, cqe, count)) {
		return -1;
	}
	for (i = 0; i < count; i++) {
		if (cqe[i]->res) {
			return cqe[i]->res;
		}
	}
	io_uring_cq_advance(ring, count);
	return 0;
}

static int run_old(struct benchmark_ctx *ctx, void *user)
{
	return run(ctx, user, process_old);
}

static int process_foreach_macro(struct io_uring *ring, struct io_uring_cqe **_,
			  unsigned count)
{
	struct io_uring_cqe *cqe;
	unsigned int head;
	io_uring_for_each_cqe(ring, head, cqe) if (cqe->res) return cqe->res;
	io_uring_cq_advance(ring, count);
	return 0;
}

static int run_foreach_macro(struct benchmark_ctx *ctx, void *user)
{
	return run(ctx, user, process_foreach_macro);
}

int main(int argc, char *argv[])
{
	struct basic_benchmark_parameter params[] = {
		basic_benchmark_params("SQE=  16 CQE=  16", 16, 16),
		basic_benchmark_params("SQE=  16 CQE= 256", 16, 256),
		basic_benchmark_params("SQE=  16 CQE=4096", 16, 4096),
		basic_benchmark_params("SQE= 256 CQE= 256", 256, 256 ),
		basic_benchmark_params("SQE=4096 CQE=4096", 4096, 4096),
		basic_benchmark_params("SQE=16384 CQE=16384", 16384, 16384),
		{}
	};
	struct benchmark_opts opts = parse_benchmark_opts(argc, argv);
	run_benchmark(&opts, "nop_old", basic_benchmark_init, run_old,
		      basic_benchmark_teardown,
		      (struct benchmark_parameter *)params, sizeof(params[0]));
	run_benchmark(&opts, "nop_foreach_macro", basic_benchmark_init,
		      run_foreach_macro, basic_benchmark_teardown,
		      (struct benchmark_parameter *)params, sizeof(params[0]));
	return 0;
}
