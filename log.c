/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
    This file is part of systemd.

    Copyright 2010 Lennart Poettering

    systemd is free software; you can redistribute it and/or modify it
    under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 2.1 of the License, or
    (at your option) any later version.

    systemd is distributed in the hope that it will be useful, but
    WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#define _GNU_SOURCE
#include <inttypes.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stddef.h>
#include <printf.h>

#include "builtins.h"
#include "variables.h"
#include "arrayfunc.h"
#include "common.h"
#include "bashgetopt.h"
#include "shell.h"

/* systemd defs */
#include <systemd/sd-messages.h>
#include "log.h"
#include <sys/resource.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include "macro.h"
#include "socket-util.h"
#include "process-util.h"
#include "terminal-util.h"
#include "signal-util.h"
/* systemd defs end */

static char *shell_invocation_short_name;

#define SNDBUF_SIZE (8*1024*1024)

static LogTarget log_target = LOG_TARGET_CONSOLE;
static int log_max_level = LOG_INFO;
static int log_facility = LOG_DAEMON;

static int console_fd = STDERR_FILENO;
static int syslog_fd = -1;
static int kmsg_fd = -1;
static int journal_fd = -1;

static bool syslog_is_stream = false;

static bool show_color = false;
static bool show_location = false;

static bool upgrade_syslog_to_journal = false;

/* Akin to glibc's __abort_msg; which is private and we hence cannot
 * use here. */
static char *log_abort_msg = NULL;


/* static void __attribute__((constructor)) init(void) */
/* { */
/*         bind_int_variable("LOG_LEVEL", "0"); */
/* } */

static void log_close_console(void) {

        if (console_fd < 0)
                return;

        if (getpid() == 1) {
                if (console_fd >= 3)
                        close(console_fd);

                console_fd = -1;
        }
}

static int log_open_console(void) {

        if (console_fd >= 0)
                return 0;

        if (getpid() == 1) {
                console_fd = open_terminal("/dev/console", O_WRONLY|O_NOCTTY|O_CLOEXEC);
                if (console_fd < 0)
                        return console_fd;
        } else
                console_fd = STDERR_FILENO;

        return 0;
}

static void log_close_kmsg(void) {
        kmsg_fd = close(kmsg_fd);
}

static int log_open_kmsg(void) {

        if (kmsg_fd >= 0)
                return 0;

        kmsg_fd = open("/dev/kmsg", O_WRONLY|O_NOCTTY|O_CLOEXEC);
        if (kmsg_fd < 0)
                return -errno;

        return 0;
}

static void log_close_syslog(void) {
        syslog_fd = close(syslog_fd);
}

static int create_log_socket(int type) {
        struct timeval tv;
        int fd;

        fd = socket(AF_UNIX, type|SOCK_CLOEXEC, 0);
        if (fd < 0)
                return -errno;

        fd_inc_sndbuf(fd, SNDBUF_SIZE);

        /* We need a blocking fd here since we'd otherwise lose
           messages way too early. However, let's not hang forever in the
           unlikely case of a deadlock. */
        if (getpid() == 1)
                timeval_store(&tv, 10 * USEC_PER_MSEC);
        else
                timeval_store(&tv, 10 * USEC_PER_SEC);
        (void) setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        return fd;
}

static int log_open_syslog(void) {

        static const union sockaddr_union sa = {
                .un.sun_family = AF_UNIX,
                .un.sun_path = "/dev/log",
        };

        int r;

        if (syslog_fd >= 0)
                return 0;

        syslog_fd = create_log_socket(SOCK_DGRAM);
        if (syslog_fd < 0) {
                r = syslog_fd;
                goto fail;
        }

        if (connect(syslog_fd, &sa.sa, offsetof(struct sockaddr_un, sun_path) + strlen(sa.un.sun_path)) < 0) {
                close(syslog_fd);

                /* Some legacy syslog systems still use stream
                 * sockets. They really shouldn't. But what can we
                 * do... */
                syslog_fd = create_log_socket(SOCK_STREAM);
                if (syslog_fd < 0) {
                        r = syslog_fd;
                        goto fail;
                }

                if (connect(syslog_fd, &sa.sa, offsetof(struct sockaddr_un, sun_path) + strlen(sa.un.sun_path)) < 0) {
                        r = -errno;
                        goto fail;
                }

                syslog_is_stream = true;
        } else
                syslog_is_stream = false;

        return 0;

 fail:
        log_close_syslog();
        return r;
}

static void log_close_journal(void) {
        close(journal_fd);
        journal_fd = -1;
}

static int log_open_journal(void) {

        static const union sockaddr_union sa = {
                .un.sun_family = AF_UNIX,
                .un.sun_path = "/run/systemd/journal/socket",
        };

        int r;

        if (journal_fd >= 0)
                return 0;

        journal_fd = create_log_socket(SOCK_DGRAM);
        if (journal_fd < 0) {
                r = journal_fd;
                goto fail;
        }

        if (connect(journal_fd, &sa.sa, offsetof(struct sockaddr_un, sun_path) + strlen(sa.un.sun_path)) < 0) {
                r = -errno;
                goto fail;
        }

        return 0;

 fail:
        log_close_journal();
        return r;
}

static int log_open(void) {
        int r;

        /* If we don't use the console we close it here, to not get
         * killed by SAK. If we don't use syslog we close it here so
         * that we are not confused by somebody deleting the socket in
         * the fs. If we don't use /dev/kmsg we still keep it open,
         * because there is no reason to close it. */

        if (log_target == LOG_TARGET_NULL) {
                log_close_journal();
                log_close_syslog();
                log_close_console();
                return 0;
        }

        if ((log_target != LOG_TARGET_AUTO && log_target != LOG_TARGET_SAFE) ||
            getpid() == 1 ||
            isatty(STDERR_FILENO) <= 0) {

                if (log_target == LOG_TARGET_AUTO ||
                    log_target == LOG_TARGET_JOURNAL_OR_KMSG ||
                    log_target == LOG_TARGET_JOURNAL) {
                        r = log_open_journal();
                        if (r >= 0) {
                                log_close_syslog();
                                log_close_console();
                                return r;
                        }
                }

                if (log_target == LOG_TARGET_SYSLOG_OR_KMSG ||
                    log_target == LOG_TARGET_SYSLOG) {
                        r = log_open_syslog();
                        if (r >= 0) {
                                log_close_journal();
                                log_close_console();
                                return r;
                        }
                }

                if (log_target == LOG_TARGET_AUTO ||
                    log_target == LOG_TARGET_SAFE ||
                    log_target == LOG_TARGET_JOURNAL_OR_KMSG ||
                    log_target == LOG_TARGET_SYSLOG_OR_KMSG ||
                    log_target == LOG_TARGET_KMSG) {
                        r = log_open_kmsg();
                        if (r >= 0) {
                                log_close_journal();
                                log_close_syslog();
                                log_close_console();
                                return r;
                        }
                }
        }

        log_close_journal();
        log_close_syslog();

        return log_open_console();
}

static void log_set_target(LogTarget target) {
        assert(target >= 0);
        assert(target < _LOG_TARGET_MAX);

        if (upgrade_syslog_to_journal) {
                if (target == LOG_TARGET_SYSLOG)
                        target = LOG_TARGET_JOURNAL;
                else if (target == LOG_TARGET_SYSLOG_OR_KMSG)
                        target = LOG_TARGET_JOURNAL_OR_KMSG;
        }

        log_target = target;
}

static void log_close(void) {
        log_close_journal();
        log_close_syslog();
        log_close_kmsg();
        log_close_console();
}

static void log_set_max_level(int level) {
        assert((level & LOG_PRIMASK) == level);

        log_max_level = level;
}

static void log_set_facility(int facility) {
        log_facility = facility;
}

static int write_to_console(
                            int level,
                            int error,
                            const char *file,
                            int line,
                            const char *func,
                            const char *object_field,
                            const char *object,
                            const char *buffer) {

        char location[64], prefix[1 + DECIMAL_STR_MAX(int) + 2];
        struct iovec iovec[6] = {};
        unsigned n = 0;
        bool highlight;

        if (console_fd < 0)
                return 0;

        if (log_target == LOG_TARGET_CONSOLE_PREFIXED) {
                sprintf(prefix, "<%i>", level);
                IOVEC_SET_STRING(iovec[n++], prefix);
        }

        highlight = LOG_PRI(level) <= LOG_ERR && show_color;

        if (show_location) {
                snprintf(location, sizeof(location), "(%s:%i) ", file, line);
                IOVEC_SET_STRING(iovec[n++], location);
        }

        if (highlight)
                IOVEC_SET_STRING(iovec[n++], ANSI_HIGHLIGHT_RED_ON);
        IOVEC_SET_STRING(iovec[n++], buffer);
        if (highlight)
                IOVEC_SET_STRING(iovec[n++], ANSI_HIGHLIGHT_OFF);
        IOVEC_SET_STRING(iovec[n++], "\n");

        if (writev(console_fd, iovec, n) < 0) {

                if (errno == EIO && getpid() == 1) {

                        /* If somebody tried to kick us from our
                         * console tty (via vhangup() or suchlike),
                         * try to reconnect */

                        log_close_console();
                        log_open_console();

                        if (console_fd < 0)
                                return 0;

                        if (writev(console_fd, iovec, n) < 0)
                                return -errno;
                } else
                        return -errno;
        }

        return 1;
}

static int write_to_syslog(
                           int level,
                           int error,
                           const char *file,
                           int line,
                           const char *func,
                           const char *object_field,
                           const char *object,
                           const char *buffer) {

        char header_priority[2 + DECIMAL_STR_MAX(int) + 1],
                header_time[64],
                header_pid[4 + DECIMAL_STR_MAX(pid_t) + 1];
        struct iovec iovec[5] = {};
        struct msghdr msghdr = {
                .msg_iov = iovec,
                .msg_iovlen = ELEMENTSOF(iovec),
        };
        time_t t;
        struct tm *tm;

        if (syslog_fd < 0)
                return 0;

        xsprintf(header_priority, "<%i>", level);

        t = (time_t) (now(CLOCK_REALTIME) / USEC_PER_SEC);
        tm = localtime(&t);
        if (!tm)
                return -EINVAL;

        if (strftime(header_time, sizeof(header_time), "%h %e %T ", tm) <= 0)
                return -EINVAL;

        xsprintf(header_pid, "[%u]: ", (unsigned int)getpid());

        IOVEC_SET_STRING(iovec[0], header_priority);
        IOVEC_SET_STRING(iovec[1], header_time);
        IOVEC_SET_STRING(iovec[2], shell_invocation_short_name);
        IOVEC_SET_STRING(iovec[3], header_pid);
        IOVEC_SET_STRING(iovec[4], buffer);

        /* When using syslog via SOCK_STREAM separate the messages by NUL chars */
        if (syslog_is_stream)
                iovec[4].iov_len++;

        for (;;) {
                ssize_t n;

                n = sendmsg(syslog_fd, &msghdr, MSG_NOSIGNAL);
                if (n < 0)
                        return -errno;

                if (!syslog_is_stream ||
                    (size_t) n >= IOVEC_TOTAL_SIZE(iovec, ELEMENTSOF(iovec)))
                        break;

                IOVEC_INCREMENT(iovec, ELEMENTSOF(iovec), n);
        }

        return 1;
}

static int write_to_kmsg(
                         int level,
                         int error,
                         const char*file,
                         int line,
                         const char *func,
                         const char *object_field,
                         const char *object,
                         const char *buffer) {

        char header_priority[2 + DECIMAL_STR_MAX(int) + 1],
                header_pid[4 + DECIMAL_STR_MAX(pid_t) + 1];
        struct iovec iovec[5] = {};

        if (kmsg_fd < 0)
                return 0;

        xsprintf(header_priority, "<%i>", level);
        xsprintf(header_pid, "[%u]: ", (unsigned int)getpid());

        IOVEC_SET_STRING(iovec[0], header_priority);
        IOVEC_SET_STRING(iovec[1], shell_invocation_short_name);
        IOVEC_SET_STRING(iovec[2], header_pid);
        IOVEC_SET_STRING(iovec[3], buffer);
        IOVEC_SET_STRING(iovec[4], "\n");

        if (writev(kmsg_fd, iovec, ELEMENTSOF(iovec)) < 0)
                return -errno;

        return 1;
}

static int log_do_header(
                         char *header,
                         size_t size,
                         int level,
                         int error,
                         const char *file, int line, const char *func,
                         const char *object_field, const char *object) {


        snprintf(header, size,
                 "PRIORITY=%i\n"
                 "SYSLOG_FACILITY=%i\n"
                 "%s%s%s"
                 "%s%.*i%s"
                 "%s%s%s"
                 "%s%.*i%s"
                 "%s%s%s"
                 "SYSLOG_IDENTIFIER=%s\n",
                 LOG_PRI(level),
                 LOG_FAC(level),
                 isempty(file) ? "" : "CODE_FILE=",
                 isempty(file) ? "" : file,
                 isempty(file) ? "" : "\n",
                 "CODE_LINE=",
                 line ? 1 : 0, line, /* %.0d means no output too, special case for 0 */
                 line ? "\n" : "",
                 isempty(func) ? "" : "CODE_FUNCTION=",
                 isempty(func) ? "" : func,
                 isempty(func) ? "" : "\n",
                 error ? "ERRNO=" : "",
                 error ? 1 : 0, error,
                 error ? "\n" : "",
                 isempty(object) ? "" : object_field,
                 isempty(object) ? "" : object,
                 isempty(object) ? "" : "\n",
                 shell_invocation_short_name);

        return 0;
}

static int write_to_journal(
                            int level,
                            int error,
                            const char*file,
                            int line,
                            const char *func,
                            const char *object_field,
                            const char *object,
                            const char *buffer) {

        char header[LINE_MAX];
        struct iovec iovec[4] = {};
        struct msghdr mh = {};

        if (journal_fd < 0)
                return 0;

        log_do_header(header, sizeof(header), level, error, file, line, func, object_field, object);

        IOVEC_SET_STRING(iovec[0], header);
        IOVEC_SET_STRING(iovec[1], "MESSAGE=");
        IOVEC_SET_STRING(iovec[2], buffer);
        IOVEC_SET_STRING(iovec[3], "\n");

        mh.msg_iov = iovec;
        mh.msg_iovlen = ELEMENTSOF(iovec);

        if (sendmsg(journal_fd, &mh, MSG_NOSIGNAL) < 0)
                return -errno;

        return 1;
}

static int log_dispatch(
                        int level,
                        int error,
                        const char *file,
                        int line,
                        const char *func,
                        const char *object_field,
                        const char *object,
                        char *buffer) {

        assert(buffer);

        if (log_target == LOG_TARGET_NULL)
                return -error;

        /* Patch in LOG_DAEMON facility if necessary */
        if ((level & LOG_FACMASK) == 0)
                level = log_facility | LOG_PRI(level);

        if (error < 0)
                error = -error;

        do {
                char *e;
                int k = 0;

                buffer += strspn(buffer, NEWLINE);

                if (buffer[0] == 0)
                        break;

                if ((e = strpbrk(buffer, NEWLINE)))
                        *(e++) = 0;

                if (log_target == LOG_TARGET_AUTO ||
                    log_target == LOG_TARGET_JOURNAL_OR_KMSG ||
                    log_target == LOG_TARGET_JOURNAL) {

                        k = write_to_journal(level, error, file, line, func, object_field, object, buffer);
                        if (k < 0) {
                                if (k != -EAGAIN)
                                        log_close_journal();
                                log_open_kmsg();
                        }
                }

                if (log_target == LOG_TARGET_SYSLOG_OR_KMSG ||
                    log_target == LOG_TARGET_SYSLOG) {

                        k = write_to_syslog(level, error, file, line, func, object_field, object, buffer);
                        if (k < 0) {
                                if (k != -EAGAIN)
                                        log_close_syslog();
                                log_open_kmsg();
                        }
                }

                if (k <= 0 &&
                    (log_target == LOG_TARGET_AUTO ||
                     log_target == LOG_TARGET_SAFE ||
                     log_target == LOG_TARGET_SYSLOG_OR_KMSG ||
                     log_target == LOG_TARGET_JOURNAL_OR_KMSG ||
                     log_target == LOG_TARGET_KMSG)) {

                        k = write_to_kmsg(level, error, file, line, func, object_field, object, buffer);
                        if (k < 0) {
                                log_close_kmsg();
                                log_open_console();
                        }
                }

                if (k <= 0)
                        (void) write_to_console(level, error, file, line, func, object_field, object, buffer);

                buffer = e;
        } while (buffer);

        return -error;
}


static int log_internalv(
                  int level,
                  int error,
                  const char*file,
                  int line,
                  const char *func,
                  const char *format,
                  va_list ap) {

        PROTECT_ERRNO;
        char buffer[LINE_MAX];

        if (error < 0)
                error = -error;

        if (_likely_(LOG_PRI(level) > log_max_level))
                return -error;

        /* Make sure that %m maps to the specified error */
        if (error != 0)
                errno = error;

        vsnprintf(buffer, sizeof(buffer), format, ap);

        return log_dispatch(level, error, file, line, func, NULL, NULL, buffer);
}

static int log_internal(
                 int level,
                 int error,
                 const char*file,
                 int line,
                 const char *func,
                 const char *format, ...) {

        va_list ap;
        int r;

        va_start(ap, format);
        r = log_internalv(level, error, file, line, func, format, ap);
        va_end(ap);

        return r;
}


static void log_assert(
                       int level,
                       const char *text,
                       const char *file,
                       int line,
                       const char *func,
                       const char *format) {

        static char buffer[LINE_MAX];

        if (_likely_(LOG_PRI(level) > log_max_level))
                return;

        DISABLE_WARNING_FORMAT_NONLITERAL;
        snprintf(buffer, sizeof(buffer), format, text, file, line, func);
        REENABLE_WARNING;

        log_abort_msg = buffer;

        log_dispatch(level, 0, file, line, func, NULL, NULL, buffer);
}

static noreturn void log_assert_failed(const char *text, const char *file, int line, const char *func) {
        log_assert(LOG_CRIT, text, file, line, func, "Assertion '%s' failed at %s:%u, function %s(). Aborting.");
        abort();
}

static noreturn void log_assert_failed_unreachable(const char *text, const char *file, int line, const char *func) {
        log_assert(LOG_CRIT, text, file, line, func, "Code should not be reached '%s' at %s:%u, function %s(). Aborting.");
        abort();
}

static void log_assert_failed_return(const char *text, const char *file, int line, const char *func) {
        PROTECT_ERRNO;
        log_assert(LOG_DEBUG, text, file, line, func, "Assertion '%s' failed at %s:%u, function %s(). Ignoring.");
}



static int log_set_target_from_string(const char *e) {
        LogTarget t;

        t = log_target_from_string(e);
        if (t < 0)
                return -EINVAL;

        log_set_target(t);
        return 0;
}

static int log_set_max_level_from_string(const char *e) {
        int t;

        t = log_level_from_string(e);
        if (t < 0)
                return t;

        log_set_max_level(t);
        return 0;
}


static void log_parse_environment(void) {
        const char *e;

        e = get_string_value("BASH_LOG_TARGET");
        if (e && log_set_target_from_string(e) < 0)
                log_warning("Failed to parse log target '%s'. Ignoring.", e);

        e = get_string_value("BASH_LOG_LEVEL");
        if (e && log_set_max_level_from_string(e) < 0)
                log_warning("Failed to parse log level '%s'. Ignoring.", e);

        e = get_string_value("BASH_LOG_COLOR");
        if (e && log_show_color_from_string(e) < 0)
                log_warning("Failed to parse bool '%s'. Ignoring.", e);

        e = get_string_value("BASH_LOG_LOCATION");
        if (e && log_show_location_from_string(e) < 0)
                log_warning("Failed to parse bool '%s'. Ignoring.", e);
}

static LogTarget log_get_target(void) {
        return log_target;
}

static int log_get_max_level(void) {
        return log_max_level;
}

static void log_show_location(bool b) {
        show_location = b;
}

static void log_show_color(bool b) {
        show_color = b;
}

static bool log_get_show_location(void) {
        return show_location;
}

static int log_show_color_from_string(const char *e) {
        int t;

        t = parse_boolean(e);
        if (t < 0)
                return t;

        log_show_color(t);
        return 0;
}

static int log_show_location_from_string(const char *e) {
        int t;

        t = parse_boolean(e);
        if (t < 0)
                return t;

        log_show_location(t);
        return 0;
}

static bool log_on_console(void) {
        if (log_target == LOG_TARGET_CONSOLE ||
            log_target == LOG_TARGET_CONSOLE_PREFIXED)
                return true;

        return syslog_fd < 0 && kmsg_fd < 0 && journal_fd < 0;
}

static const char *const log_target_table[_LOG_TARGET_MAX] = {
        [LOG_TARGET_CONSOLE] = "console",
        [LOG_TARGET_CONSOLE_PREFIXED] = "console-prefixed",
        [LOG_TARGET_KMSG] = "kmsg",
        [LOG_TARGET_JOURNAL] = "journal",
        [LOG_TARGET_JOURNAL_OR_KMSG] = "journal-or-kmsg",
        [LOG_TARGET_SYSLOG] = "syslog",
        [LOG_TARGET_SYSLOG_OR_KMSG] = "syslog-or-kmsg",
        [LOG_TARGET_AUTO] = "auto",
        [LOG_TARGET_SAFE] = "safe",
        [LOG_TARGET_NULL] = "null"
};

DEFINE_STRING_TABLE_LOOKUP(log_target, LogTarget);

static void log_set_upgrade_syslog_to_journal(bool b) {
        upgrade_syslog_to_journal = b;
}

/*********************************************************/

static usec_t timespec_load(const struct timespec *ts) {
        assert(ts);

        if (ts->tv_sec == (time_t) -1 &&
            ts->tv_nsec == (long) -1)
                return USEC_INFINITY;

        if ((usec_t) ts->tv_sec > (UINT64_MAX - (ts->tv_nsec / NSEC_PER_USEC)) / USEC_PER_SEC)
                return USEC_INFINITY;

        return
                (usec_t) ts->tv_sec * USEC_PER_SEC +
                (usec_t) ts->tv_nsec / NSEC_PER_USEC;
}

static usec_t now(clockid_t clock_id) {
        struct timespec ts;

        assert_se(clock_gettime(clock_id, &ts) == 0);

        return timespec_load(&ts);
}

static const char *const log_level_table[] = {
        [LOG_EMERG] = "emerg",
        [LOG_ALERT] = "alert",
        [LOG_CRIT] = "crit",
        [LOG_ERR] = "err",
        [LOG_WARNING] = "warning",
        [LOG_NOTICE] = "notice",
        [LOG_INFO] = "info",
        [LOG_DEBUG] = "debug"
};

DEFINE_STRING_TABLE_LOOKUP_WITH_FALLBACK(log_level, int, LOG_DEBUG);

static bool streq_ptr(const char *a, const char *b) {

        /* Like streq(), but tries to make sense of NULL pointers */

        if (a && b)
                return streq(a, b);

        if (!a && !b)
                return true;

        return false;
}

static ssize_t string_table_lookup(const char * const *table, size_t len, const char *key) {
        size_t i;

        if (!key)
                return -1;

        for (i = 0; i < len; ++i)
                if (streq_ptr(table[i], key))
                        return (ssize_t)i;

        return -1;
}

static struct timeval *timeval_store(struct timeval *tv, usec_t u) {
        assert(tv);

        if (u == USEC_INFINITY) {
                tv->tv_sec = (time_t) -1;
                tv->tv_usec = (suseconds_t) -1;
        } else {
                tv->tv_sec = (time_t) (u / USEC_PER_SEC);
                tv->tv_usec = (suseconds_t) (u % USEC_PER_SEC);
        }

        return tv;
}

static int fd_inc_sndbuf(int fd, size_t n) {
        int r, value;
        socklen_t l = sizeof(value);

        r = getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &value, &l);
        if (r >= 0 && l == sizeof(value) && (size_t) value >= n*2)
                return 0;

        /* If we have the privileges we will ignore the kernel limit. */

        value = (int) n;
        if (setsockopt(fd, SOL_SOCKET, SO_SNDBUFFORCE, &value, sizeof(value)) < 0)
                if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &value, sizeof(value)) < 0)
                        return -errno;

        return 1;
}

/*********************************************************/

static int bash_log_open(WORD_LIST *list)
{
        int opt;
        reset_internal_getopt();
        while ((opt = internal_getopt(list, "")) != -1) {
                switch (opt) {
                default:
                        builtin_usage();
                        return 1;
                }
        }
        if ((list = loptend) == NULL) {
                shell_invocation_short_name = strdup(basename(get_string_value("BASH_SOURCE")));
        } else {
                shell_invocation_short_name = strdup(list->word->word);
        }

        log_set_target(LOG_TARGET_JOURNAL);
        log_parse_environment();
        return log_open();
}

static int bash_log_close(WORD_LIST *list)
{
        int opt;
        reset_internal_getopt();
        while ((opt = internal_getopt(list, "")) != -1) {
                switch (opt) {
                default:
                        builtin_usage();
                        return 1;
                }
        }
        if ((list = loptend) != NULL) {
                        builtin_usage();
                        return 1;
        }
        log_close();
        return 0;
}

static int log_msg(WORD_LIST *list)
{
        int opt;
        size_t len = 0;
        WORD_LIST *lit;
        char *buf = NULL;
        int ret;

        reset_internal_getopt();
        while ((opt = internal_getopt(list, "")) != -1) {
                switch (opt) {
                default:
                        builtin_usage();
                        return 1;
                }
        }

        if ((list = loptend) == NULL) {
                builtin_usage();
                return 1;
        }

        for (lit = list; lit; lit = lit->next) {
                len += strlen(lit->word->word) + 1;
        }
        buf = malloc(len);
        if (!buf) {
                return log_oom();
        }
        buf[0] = 0;
        for (lit = list; lit; lit = lit->next) {
                strcat(buf, lit->word->word);
                if (lit->next)
                        strcat(buf, " ");
        }

        ret = log_dispatch(LOG_INFO, 0,
                            get_string_value("BASH_SOURCE"),
                            atoi(get_string_value("LINENO")),
                            get_string_value("FUNCNAME"),
                            NULL,
                            NULL,
                            buf);
        free(buf);
        return ret;
}

static char *log_open_usage[] = {
        "Open the log.",
        "",
        "Blah, Blah",
        "",
        "Usage:",
        "",
        "   $ log_open [[<name>] <target>]"
        "",
        NULL,
};

struct builtin __attribute__((visibility("default"))) log_open_struct = {
        .name       = "log_open",
        .function   = bash_log_open,
        .flags      = BUILTIN_ENABLED,
        .long_doc   = log_open_usage,
        .short_doc  = "log_open",
        .handle     = NULL,
};

static char *log_close_usage[] = {
        "Close the log.",
        "",
        "Blah, Blah",
        "",
        "Usage:",
        "",
        "   $ log_close"
        "",
        NULL,
};

struct builtin __attribute__((visibility("default"))) log_close_struct = {
        .name       = "log_close",
        .function   = bash_log_close,
        .flags      = BUILTIN_ENABLED,
        .long_doc   = log_close_usage,
        .short_doc  = "log_close",
        .handle     = NULL,
};

static char *log_msg_usage[] = {
        "Log a message.",
        "",
        "Blah, Blah",
        "",
        "Usage:",
        "",
        "   $ log_msg "
        "",
        NULL,
};

struct builtin __attribute__((visibility("default"))) log_msg_struct = {
        .name       = "log_msg",
        .function   = log_msg,
        .flags      = BUILTIN_ENABLED,
        .long_doc   = log_msg_usage,
        .short_doc  = "log_msg",
        .handle     = NULL,
};
