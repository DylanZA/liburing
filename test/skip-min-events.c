/* SPDX-License-Identifier: MIT */

#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <poll.h>
#include <assert.h>
#include <sys/eventfd.h>
#include <stdatomic.h>
#include <pthread.h>

#include "liburing.h"
#include "helpers.h"

static bool has_skip = true;

enum wait_details_state {
	INIT,
	ABOUT_TO_WAIT,
	WAIT_SUCCESS,
	WAIT_FAIL
};

struct wait_details {
	struct io_uring *ring;
	unsigned submit_count;
	unsigned wait_count;
	atomic_int state;
	int result;
};

static void *wait_thread(void *data)
{
	struct wait_details *w = (struct wait_details *)data;

	w->state = ABOUT_TO_WAIT;
	w->result = io_uring_submit_and_wait(w->ring, w->wait_count);
	w->state = w->result != w->submit_count ? WAIT_FAIL : WAIT_SUCCESS;

	return NULL;
}

static int test(int reads)
{
	struct io_uring_sqe *sqe;
	struct io_uring ring;
	pthread_t thread;
	int ret;
	int fds[2 * reads];
	struct wait_details thread_wait;
	int buf;
	int i;

	ret = io_uring_queue_init(32, &ring, 0);
	assert(!ret);

	if (!(ring.features & IORING_FEAT_CQE_SKIP_MIN_EVENTS)) {
		has_skip = false;
		return 0;
	}

	for (i = 0; i < reads; i++) {
		ret = pipe(&fds[i * 2]);
		assert(!ret);
	}

	sqe = io_uring_get_sqe(&ring);
	assert(sqe);
	io_uring_prep_nop(sqe);
	io_uring_sqe_set_data64(sqe, 1);
	sqe->flags |= IOSQE_CQE_SKIP_MIN_EVENTS;

	for (i = 0; i < reads; i++) {
		sqe = io_uring_get_sqe(&ring);
		assert(sqe);
		io_uring_prep_read(sqe, fds[i * 2], &buf, 1, 0);
		io_uring_sqe_set_data64(sqe, 2);
		if (i < reads -1) {
			sqe->flags |= IOSQE_CQE_SKIP_MIN_EVENTS;
			sqe->flags |= IOSQE_IO_LINK;
		}
	}

	thread_wait = (struct wait_details) {
		.ring = &ring,
		.submit_count = reads + 1,
		.wait_count = 1,
		.state = INIT
	};
	ret = pthread_create(&thread, NULL, wait_thread, &thread_wait);
	assert(!ret);

	usleep(50000);

	for (i = 0; i < reads; i++) {
		/* by now it should still not have woken up */
		if (thread_wait.state != ABOUT_TO_WAIT) {
			fprintf(stderr, "expected to be waiting i=%d/%d\n", i, reads);
			ret = 1;
			goto done;
		}

		ret = write(fds[i * 2 + 1], &buf, 1);
		assert(ret == 1);
		usleep(10000);
	}

	ret = pthread_join(thread, NULL);
	assert(!ret);

	if (thread_wait.state != WAIT_SUCCESS) {
		fprintf(stderr, "bad submit_and_wait %d\n", thread_wait.result);
		ret = 1;
		goto done;
	}
	if (io_uring_cq_ready(&ring) != reads + 1) {
		fprintf(stderr, "wanted %d but have %u entries\n", reads + 1, io_uring_cq_ready(&ring));
		ret = 1;
		goto done;
	}
	ret = 0;
done:
	io_uring_queue_exit(&ring);
	for (i = 0; i < reads * 2; i++) {
		close(fds[i]);
	}
	return ret;
}

int main(int argc, char *argv[])
{
	int ret;

	if (argc > 1)
		return T_EXIT_SKIP;

	ret = test(1);
	if (!has_skip)
		return T_EXIT_SKIP;
	if (ret) {
		fprintf(stderr, "%s: test(1) failed\n", argv[0]);
		return T_EXIT_FAIL;
	}

	/* unclear if this should work.
	 * it implies we don't wake up even if it wasnt completed on the initial submit
	 */
	ret = test(2);
	if (ret) {
		fprintf(stderr, "%s: test(2) failed\n", argv[0]);
		return T_EXIT_FAIL;
	}

	return ret;
}
