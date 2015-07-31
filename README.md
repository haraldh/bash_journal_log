# bash_journal_log

This is WORK IN PROGRESS! DO NOT USE IN PRODUCTION!

This is `bash_journal_log`, a systemd journal interface for bash.

`bash_journal_log` is a bash plugin that provides the systemd logging infrastructure directly
in your shell.

A (very) simple example will help illustrate:

```bash
$ BASH_LOG_TARGET=journal-or-kmsg log_open MYAPP
$ log_msg "Hello World"
$ journalctl -e | tail -1
Jul 31 19:55:58 MYAPP[6994]: Hello World
```

See the test.sh file in the git tree.

Also bash_journal_log logs
* CODE_FILE=$BASH_SOURCE
* CODE_LINE=$LINENO
* CODE_FUNCTION=$FUNCNAME[0]

