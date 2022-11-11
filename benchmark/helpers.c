#include "helpers.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <assert.h>

static uint64_t current_time_ms(void)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts))
		exit(1);
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

bool loop_check_slow(struct benchmark_ctx *ctx, unsigned int count)
{
	struct benchmark_loop_ctx *c = &ctx->loop;
	uint64_t now = current_time_ms();
	bool ret = now < c->end;
	unsigned long long diff;

	c->count += count;
	if (!c->next_log || now < c->next_log)
		return ret;

	/* now log */
	diff = c->count - c->last_count;
	if (diff && c->last_log && c->last_log != now) {
		fprintf(stderr, "%llu k/s\n", diff / (now - c->last_log));
	}
	c->last_log = now;
	c->next_log = now + 1000;
	c->last_count = c->count;
	return ret;
}

struct run_result {
	int ret;
	uint64_t end;
	uint64_t start;
	uint64_t count;
};

static uint64_t run_res_k_per(struct run_result const *r)
{
	if (r->end == r->start)
		return 0;
	return r->count / (r->end - r->start);
}

static uint64_t avg_run_res_k_per(struct run_result const *r, int n)
{
	uint64_t acc = 0;
	int i;

	if (n <= 0)
		return 0;

	for (i = 0; i < n; i++)
		acc += run_res_k_per(r + i);

	return acc / n;
}


static struct run_result _run_one(benchmark_init_user init, benchmark_run run,
				  benchmark_teardown_user teardown,
				  struct benchmark_parameter *param,
				  struct benchmark_ctx ctx)
{
	ctx.param = param;
	ctx.loop = (struct benchmark_loop_ctx){};

	void *user = NULL;
	struct run_result res = {};

	res.ret = init(&ctx, &user);
	if (res.ret)
		goto err;
	res.start = current_time_ms();
	ctx.loop.end = res.start + ctx.run_ms;
	if (ctx.log_continuously)
		ctx.loop.next_log = res.start + 1000;

	res.ret = run(&ctx, user);
	res.end = current_time_ms();

	teardown(&ctx, user);
	res.count = ctx.loop.count;
err:
	return res;
}

struct benchmark_opts parse_benchmark_opts(int argc, char *argv[])
{
	struct benchmark_opts opts = {
		.select_idx = -1,
		.run_ms = 2000,
		.runs = 1,
	};
	int opt;

	while ((opt = getopt(argc, argv, "lt:s:n:r:")) != -1) {
		switch (opt) {
		case 'l':
			opts.list = true;
			break;
		case 'n':
			opts.select_name = optarg;
			break;
		case 's':
			opts.select_idx = atoi(optarg);
			opts.run_ms = 99999999;
			break;
		case 't':
			opts.run_ms = atoi(optarg);
			break;
		case 'r':
			opts.runs = atoi(optarg);
			break;
		default:
			fprintf(stderr,
				"Usage: %s [-t msecs] [-s select] [-r runs] [-l]\n",
				argv[0]);
			exit(-1);
		}
	}
	return opts;
}

static int rescomp(void const* va, void const* vb)
{
	struct run_result const *a = va;
	struct run_result const *b = vb;
	uint64_t ra = run_res_k_per(a);
	uint64_t rb = run_res_k_per(b);
	if (ra < rb)
		return -1;
	if (rb < ra)
		return 1;
	return 0;
}

static void run_one(struct benchmark_opts *opts, benchmark_init_user init, benchmark_run run,
		    benchmark_teardown_user teardown,
		    struct benchmark_parameter *param)
{
	int i;
	struct run_result *res = (struct run_result *)malloc(sizeof(*res) * opts->runs);
	struct benchmark_ctx base = {
		.run_ms = opts->run_ms,
		.log_continuously = opts->select_idx >= 0,
	};

	assert(res);

	for (i = 0; i < opts->runs; i++) {
		res[i] = _run_one(init, run, teardown, param, base);
		if (res[i].ret) {
			fprintf(stderr, "\t%-30s\tfailed (%d) (run %d)\n", param->name, res[i].ret, i);
			goto cleanup;
		}
	}

	qsort(res, opts->runs, sizeof(*res), rescomp);

	fprintf(stderr, "\t%-30s\t", param->name);
	fprintf(stderr, "%lu k/s", avg_run_res_k_per(res, opts->runs));
	if (opts->runs > 1) {
		fprintf(stderr, " p0=%lu k/s p50=%lu k/s p100=%lu k/s",
			run_res_k_per(res),
			run_res_k_per(res + (opts->runs / 2)),
			run_res_k_per(res + opts->runs - 1));
	}
	fprintf(stderr, "\n");
cleanup:
	free(res);
}

void run_benchmark(struct benchmark_opts *opts, const char *name,
		   benchmark_init_user init, benchmark_run run,
		   benchmark_teardown_user teardown,
		   struct benchmark_parameter *param,
		   size_t param_size)
{
	int select = opts->select_idx;
	int i;

	if (opts->select_name && strcmp(name, opts->select_name))
		return;

	fprintf(stderr, "%s:\n", name);
	for (i = 0; param->name;
	     i++, param = (struct benchmark_parameter *)((char*)param + param_size)) {
		if (opts->list) {
			fprintf(stderr, "%d: %s\n", i, param->name);
			continue;
		}
		if (select >= 0 && i != select) {
			continue;
		}
		if (select >= 0)
			fprintf(stderr, "selecting %d: %s\n", i, param->name);
		run_one(opts, init, run, teardown, param);
	}
}

int basic_benchmark_init_flags(struct benchmark_ctx *ctx, void **user,
			       int flags)
{
	struct io_uring_params params;
	int ret;
	struct basic_benchmark_ctx *u = (struct basic_benchmark_ctx *)malloc(
		sizeof(struct basic_benchmark_ctx));
	struct basic_benchmark_parameter *basic_p =
		(struct basic_benchmark_parameter *)ctx->param;

	if (!u)
		return -1;

	memset(u, 0, sizeof(*u));
	memset(&params, 0, sizeof(params));
	params.flags = flags;
	params.flags |= IORING_SETUP_CQSIZE;
	params.cq_entries = basic_p->cqe;

	ret = io_uring_queue_init_params(basic_p->sqe, &u->ring,
					 &params);
	if (ret) {
		free(u);
		return ret;
	}

	*user = u;
	return 0;
}

int basic_benchmark_add_provided_buffers(
	struct basic_benchmark_ctx* ctx,
	uint16_t bgid,
	int count,
	unsigned int size)
{
	struct io_uring_buf_reg reg;
	int i;

	if (ctx->buf_ring_buffer || ctx->buf_ring)
		return -EBUSY;

	if (posix_memalign((void**)&ctx->buf_ring, 4096, count * sizeof(struct io_uring_buf)))
		return -1;

	ctx->buf_ring_each_buffer_size = size;
	ctx->buf_ring_buffer = malloc(count * size);
	if (!ctx->buf_ring_buffer)
		return -ENOMEM;

	io_uring_buf_ring_init(ctx->buf_ring);
	reg = (struct io_uring_buf_reg) {
		.ring_addr = (uint64_t)ctx->buf_ring,
		.ring_entries = count,
		.bgid = bgid
	};

	if (io_uring_register_buf_ring(&ctx->ring,
					&reg,
					0)) {
		fprintf(stderr, "unable to register buf_ring\n");
		return -1;
	}


	for (i = 0; i < count; i++) {
		io_uring_buf_ring_add(ctx->buf_ring,
				basic_benchmark_provided_buffer(ctx, i, size),
				size,
				i,
				io_uring_buf_ring_mask(count),
				i);
	}
	io_uring_buf_ring_advance(ctx->buf_ring, count);
	return 0;
}

void basic_benchmark_teardown(struct benchmark_ctx *ctx, void *user)
{
	struct basic_benchmark_ctx *u = user;
	io_uring_queue_exit(&u->ring);

	if (u->buf_ring_buffer)
		free(u->buf_ring_buffer);

	/* if (u->buf_ring) */
	/* 	free(u->buf_ring); */

	free(u);
}
