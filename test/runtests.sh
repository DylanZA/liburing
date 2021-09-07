#!/bin/bash

TESTS=("$@")
RET=0
TIMEOUT=60
DMESG_FILTER="cat"
TEST_DIR=$(dirname "$0")
FAILED=""
SKIPPED=""
TIMED_OUT=""
TEST_FILES=""
declare -A TEST_MAP

# Only use /dev/kmsg if running as root
DO_KMSG="1"
[ "$(id -u)" != "0" ] && DO_KMSG="0"

# Include config.local if exists and check TEST_FILES for valid devices
if [ -f "$TEST_DIR/config.local" ]; then
	# shellcheck disable=SC1091
	. "$TEST_DIR/config.local"
	for dev in $TEST_FILES; do
		if [ ! -e "$dev" ]; then
			echo "Test file $dev not valid"
			exit 1
		fi
	done
	for dev in "${TEST_MAP[@]}"; do
		if [ ! -e "$dev" ]; then
			echo "Test file in map $dev not valid"
			exit 1
		fi
	done
fi

_check_dmesg()
{
	local dmesg_marker="$1"
	local seqres="$2.seqres"

	if [ "$DO_KMSG" -eq 0 ]; then
		return 0
	fi

	dmesg | bash -c "$DMESG_FILTER" | grep -A 9999 "$dmesg_marker" >"${seqres}.dmesg"
	grep -q -e "kernel BUG at" \
	     -e "WARNING:" \
	     -e "BUG:" \
	     -e "Oops:" \
	     -e "possible recursive locking detected" \
	     -e "Internal error" \
	     -e "INFO: suspicious RCU usage" \
	     -e "INFO: possible circular locking dependency detected" \
	     -e "general protection fault:" \
	     -e "blktests failure" \
	     "${seqres}.dmesg"
	# shellcheck disable=SC2181
	if [[ $? -eq 0 ]]; then
		return 1
	else
		rm -f "${seqres}.dmesg"
		return 0
	fi
}

run_test()
{
	local test_name="$1"
	local dev="$2"
	local test_exec=("./$test_name")
	local test_string="$test_name"
	local out_name="$test_name"

	# Specify test string to print
	if [ -n "$dev" ]; then
		test_exec+=("$dev")
		test_string="$test_name $dev"
		local suffix
		suffix=$(basename "$dev")
		out_name="$out_name.$suffix"
	fi

	# Log start of the test
	if [ "$DO_KMSG" -eq 1 ]; then
		local dmesg_marker="Running test $test_string:"
		echo "$dmesg_marker" > /dev/kmsg
	else
		local dmesg_marker=""
	fi
	printf "Running test %-25s" "$test_string"

	# Do we have to exclude the test ?
	echo "$TEST_EXCLUDE" | grep -w "$test_name" > /dev/null 2>&1
	# shellcheck disable=SC2181
	if [ $? -eq 0 ]; then
		echo "Test skipped"
		SKIPPED="$SKIPPED <$test_string>"
		return
	fi

	# Run the test
	T_START=$(date +%s)
	timeout -s INT -k $TIMEOUT $TIMEOUT "${test_exec[@]}"
	T_END=$(date +%s)
	local status=$?

	if [ -e ./core ]; then
		mv core "core-$test_name"
	fi

	# Check test status
	if [ "$status" -eq 124 ]; then
		echo "Test $test_name timed out (may not be a failure)"
		TIMED_OUT="$TIMED_OUT <$test_string>"
	elif [ "$status" -ne 0 ]; then
		echo "Test $test_name failed with ret $status"
		FAILED="$FAILED <$test_string>"
		RET=1
	elif ! _check_dmesg "$dmesg_marker" "$test_name"; then
		echo "Test $test_name failed dmesg check"
		FAILED="$FAILED <$test_string>"
		RET=1
	else
		if [ -f "output/$out_name" ]; then
			T_PREV=$(cat "output/$out_name")
		else
			T_PREV=""
		fi
		T_DIFF=$((T_END-T_START))
		if [ -n "$T_PREV" ]; then
			echo "$T_DIFF sec [$T_PREV]"
		else
			echo "$T_DIFF sec"
		fi
		echo $T_DIFF > "output/$out_name"
	fi
}

# Run all specified tests
for tst in "${TESTS[@]}"; do
	if [ ! -d output ]; then
		mkdir output
	fi
	if [ -z "${TEST_MAP[$tst]}" ]; then
		run_test "$tst"
		if [ -n "$TEST_FILES" ]; then
			for dev in $TEST_FILES; do
				run_test "$tst" "$dev"
			done
		fi
	else
		run_test "$tst" "${TEST_MAP[$tst]}"
	fi
done

if [ -n "$SKIPPED" ]; then
	echo "Tests skipped: $SKIPPED"
fi

if [ -n "$TIMED_OUT" ]; then
	echo "Tests timed out: $TIMED_OUT"
fi

if [ "${RET}" -ne 0 ]; then
	echo "Tests failed: $FAILED"
	exit $RET
else
	echo "All tests passed"
	exit 0
fi
