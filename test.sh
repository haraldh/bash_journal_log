#!/bin/bash

# dlopen the log builtin bash module
enable -f ./log.so log_open log_msg log_close

BASH_LOG_TARGET=journal-or-kmsg log_open MYAPP

if ! log_msg "Hello World!"; then
    echo "Test failed! rc=$?"
fi

test_func() {
    log_msg "Hello" "World" "from" "a" "function!"
}

test_func

eval 'log_msg "Hello World" "from eval!"'

log_close

l=$(log_msg "After log_close" 2>&1)
if [[ $l != "After log_close" ]]; then
    echo "Test failed after log_close"
fi

journalctl --no-pager -t MYAPP -n3 -o verbose
exit 0
