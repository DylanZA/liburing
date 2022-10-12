/* SPDX-License-Identifier: MIT */
#include <sys/eventfd.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <liburing.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/time.h>
#include <assert.h>
#include <sys/timerfd.h>

static int test_eventfd(void)
{
	struct io_uring_sqe *sqe;
	struct io_uring ring;
	int efd, tfd, ret;
	uint64_t buf, buf2, tbuf;
	struct itimerspec ts = {
		.it_value = {
			.tv_sec = 2,
		}
	};

	efd = eventfd(0, 0);
	assert(efd >= 0);

	tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
	assert(tfd >= 0);

	ret = io_uring_queue_init(8, &ring, IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_TASKRUN_FLAG | IORING_SETUP_COOP_TASKRUN);
	if (ret) {
		fprintf(stderr, "Unable to setup io_uring: %s\n", strerror(-ret));
		return 1;
	}

	sqe = io_uring_get_sqe(&ring);
	ret = timerfd_settime(tfd, 0, &ts, NULL);
	assert(!ret);
	io_uring_prep_read(sqe, tfd, &tbuf, sizeof(tbuf), 0);
	sqe->user_data = 1;
	sqe->flags = IOSQE_IO_HARDLINK;

	buf = 1234;
	sqe = io_uring_get_sqe(&ring);
	io_uring_prep_write(sqe, efd, &buf, sizeof(buf), 0);
	sqe->user_data = 2;
	ret = io_uring_submit(&ring);
	if (ret != 2) {
		fprintf(stderr, "ring_submit=%d\n", ret);
		return 1;
	}

	fprintf(stderr, "reading...\n");
	ret = read(efd, &buf2, sizeof(buf2));
	printf("got read %d\n", ret);

	io_uring_queue_exit(&ring);
	return 0;
}

int main(int argc, char *argv[])
{
	int ret;

	if (argc > 1)
		return 0;

	ret = test_eventfd();
	if (ret) {
		fprintf(stderr, "test_eventfd failed\n");
		return ret;
	}

	return 0;
}
