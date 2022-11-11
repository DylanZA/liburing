#ifndef LIBURING_BENCH_HELPERS_H
#define LIBURING_BENCH_HELPERS_H

#include "liburing.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

struct benchmark_ctx;
typedef bool (*benchmark_checker)(struct benchmark_ctx *, unsigned int);

struct benchmark_loop_ctx {
	unsigned int outer_count;
	uint64_t end;
	unsigned long long count;
	uint64_t next_log;
	unsigned long long last_count;
	uint64_t last_log;
};

struct benchmark_parameter {
	const char *name;
};

struct basic_benchmark_parameter {
	struct benchmark_parameter base;
	int sqe;
	int cqe;
};

struct benchmark_opts {
	unsigned int run_ms;
	const char *select_name;
	int select_idx;
	bool list;
	int runs;
};

struct benchmark_ctx {
	struct benchmark_loop_ctx loop;
	struct benchmark_parameter *param;
	unsigned int run_ms;
	bool log_continuously;
};

bool loop_check_slow(struct benchmark_ctx *ctx, unsigned int count);

#define BENCH_LOOP_OUTER (1 << 13)
#define BENCH_LOOP_START()                                                     \
	do {                                                                   \
		uint64_t __outer;                                              \
		for (__outer = 0; __outer < BENCH_LOOP_OUTER; __outer++)


#define BENCH_LOOP_END(ctx, count)                                             \
	}                                                                      \
	while (loop_check((ctx), (count)*BENCH_LOOP_OUTER, BENCH_LOOP_OUTER))

#define BENCH_LOOP_SLOW_OUTER (1 << 4)
#define BENCH_LOOP_SLOW_START()                                                     \
	do {                                                                   \
		uint64_t __outer;                                              \
		for (__outer = 0; __outer < BENCH_LOOP_SLOW_OUTER; __outer++)


#define BENCH_LOOP_SLOW_END(ctx, count)                                             \
	}                                                                      \
	while (loop_check((ctx), (count)*BENCH_LOOP_SLOW_OUTER, BENCH_LOOP_SLOW_OUTER ))

static inline bool loop_check(struct benchmark_ctx *ctx, unsigned int count, unsigned int max_loop_count)
{
	ctx->loop.outer_count += count;
	if (__builtin_expect(ctx->loop.outer_count < max_loop_count, 1))
		return true;
	ctx->loop.outer_count = 0;
	return loop_check_slow(ctx, count);
}

typedef int benchmark_run(struct benchmark_ctx *ctx, void *user);
typedef int benchmark_init_user(struct benchmark_ctx *ctx, void **user);
typedef void benchmark_teardown_user(struct benchmark_ctx *ctx, void *user);

struct benchmark_opts parse_benchmark_opts(int argc, char *argv[]);
void run_benchmark(struct benchmark_opts *opts, const char *name,
		   benchmark_init_user init, benchmark_run run,
		   benchmark_teardown_user teardown,
		   struct benchmark_parameter *params,
		   size_t param_size);

struct basic_benchmark_ctx {
	struct io_uring ring;
	void *spare;


	int buf_ring_each_buffer_size;
	char *buf_ring_buffer;
	struct io_uring_buf_ring *buf_ring;
};

int basic_benchmark_init_flags(struct benchmark_ctx *ctx, void **user,
			       int flags);

static inline int basic_benchmark_init(struct benchmark_ctx *ctx, void **user)
{
	return basic_benchmark_init_flags(ctx, user, 0);
}
void basic_benchmark_teardown(struct benchmark_ctx *ctx, void *user);

static inline struct basic_benchmark_parameter
basic_benchmark_params(const char* name, uint32_t sqe_length, uint32_t cqe_length)
{
	return (struct basic_benchmark_parameter){
		.base = (struct benchmark_parameter) {
			.name = name
		},
		.sqe = sqe_length,
		.cqe = cqe_length
	};
}

int basic_benchmark_add_provided_buffers(
	struct basic_benchmark_ctx* ctx,
	uint16_t bgid,
	int count,
	unsigned int size);

static inline void *basic_benchmark_provided_buffer(
	struct basic_benchmark_ctx* ctx,
	int i,
	unsigned int size)
{
	return ctx->buf_ring_buffer + (i * size);
}

static inline void basic_benchmark_add_buffer(
	struct basic_benchmark_ctx* ctx,
	int i,
	unsigned int size,
	uint16_t bgid)
{
	io_uring_buf_ring_add(ctx->buf_ring,
			basic_benchmark_provided_buffer(ctx, i, size),
			size,
			i,
			io_uring_buf_ring_mask(size),
			0);
	io_uring_buf_ring_advance(ctx->buf_ring, 1);
}

static inline uint32_t basic_benchmark_sqe_length(struct benchmark_ctx *ctx)
{
	return ((struct basic_benchmark_parameter*)ctx->param)->sqe;
}

static inline uint32_t basic_benchmark_cqe_length(struct benchmark_ctx *ctx)
{
	return ((struct basic_benchmark_parameter*)ctx->param)->cqe;
}

#endif
