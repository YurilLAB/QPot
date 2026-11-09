/*
 * Session plaintext capture for a disposable honeypot backend.
 *
 * When sshd logs to its standard error (-e) and that is a pipe (the
 * container's log stream), each re-executed connection process records on it,
 * beside its own log lines: the same descriptor every sshd process holds for
 * logging, so nothing is added to any process. The pre-auth network child
 * never records, and sessions get their own standard error as always. After
 * authentication the session process writes one line per record:
 *
 *   <connection> <channel> <sequence> <kind> <milliseconds> <base64>\n
 *
 * Every line is at most PIPE_BUF bytes and goes out in one write(2), so lines
 * from concurrent connections never interleave. Kinds: c command chunk and C
 * command truncated (both before their open record), o open, i input, O
 * output, e error output, t capture truncated, x exit status, z channel freed
 * (after its last data). Milliseconds count from the channel's start. A record
 * line ends in a bare newline, while sshd ends every log line with a carriage
 * return too, so the two never parse as each other. Nothing here logs: a
 * capture that cannot be written is dropped, never reported to the session.
 */

#include "includes.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#ifdef HAVE_SYS_PRCTL_H
#include <sys/prctl.h>
#endif

#include <errno.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "packet.h"
#include "channels.h"
#include "misc.h"
#include "qpcapture.h"

#define QPC_RAW_CHUNK	2048
#define QPC_LINE_MAX	4096
#define QPC_COMMAND_MAX	(16 * 1024)
#define QPC_CHAN_BUDGET	(8ULL * 1024 * 1024)
#define QPC_CONN_BUDGET	(64ULL * 1024 * 1024)
#define QPC_MAX_CHANS	64

struct qpc_chan {
	int used;
	int id;
	int truncated;
	unsigned long seq;
	unsigned long long bytes;
	struct timespec start;
};

static int qpc_fd = -1;
static char qpc_conn[33];
static struct qpc_chan qpc_chans[QPC_MAX_CHANS];
static unsigned long long qpc_conn_bytes;

static long long
qpc_elapsed_ms(const struct timespec *start)
{
	struct timespec now;

	monotime_ts(&now);
	return (long long)(now.tv_sec - start->tv_sec) * 1000 +
	    (now.tv_nsec - start->tv_nsec) / 1000000;
}

static struct qpc_chan *
qpc_find(int id)
{
	int i;

	for (i = 0; i < QPC_MAX_CHANS; i++)
		if (qpc_chans[i].used && qpc_chans[i].id == id)
			return &qpc_chans[i];
	return NULL;
}

/* Emits one record; len must not exceed QPC_RAW_CHUNK. */
static void
qpc_emit(struct qpc_chan *c, char kind, const u_char *data, size_t len)
{
	char line[QPC_LINE_MAX];
	int prefix, encoded;
	size_t total;
	ssize_t n;

	if (qpc_fd == -1 || len > QPC_RAW_CHUNK)
		return;
	prefix = snprintf(line, sizeof(line), "%s %d %lu %c %lld ",
	    qpc_conn, c->id, c->seq, kind, qpc_elapsed_ms(&c->start));
	if (prefix < 0 || (size_t)prefix >= sizeof(line))
		return;
	if (len == 0) {
		line[prefix] = '\0';
		encoded = 0;
	} else if ((encoded = b64_ntop(data, len, line + prefix,
	    sizeof(line) - prefix - 1)) < 0)
		return;
	total = (size_t)prefix + (size_t)encoded;
	line[total++] = '\n';
	c->seq++;
	for (;;) {
		n = write(qpc_fd, line, total);
		if (n == -1 && errno == EINTR)
			continue;
		break;
	}
	if (n != (ssize_t)total)
		qpc_fd = -1;	/* stream gone: stop capturing quietly */
}

static void
qpc_emit_text(struct qpc_chan *c, char kind, const char *fmt, ...)
{
	char text[QPC_RAW_CHUNK];
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vsnprintf(text, sizeof(text), fmt, ap);
	va_end(ap);
	if (n < 0)
		return;
	if ((size_t)n >= sizeof(text))
		n = sizeof(text) - 1;
	qpc_emit(c, kind, (const u_char *)text, (size_t)n);
}

static void
qpc_observe(int id, int kind, const u_char *data, size_t len)
{
	struct qpc_chan *c;
	unsigned long long room;
	size_t keep, chunk;
	char tag;

	if (qpc_fd == -1 || (c = qpc_find(id)) == NULL)
		return;
	if (kind == CHANNEL_OBSERVE_FREED) {
		qpc_emit(c, 'z', NULL, 0);
		c->used = 0;
		return;
	}
	if (kind == CHANNEL_OBSERVE_OUT)
		tag = 'O';
	else if (kind == CHANNEL_OBSERVE_IN)
		tag = 'i';
	else if (kind == CHANNEL_OBSERVE_ERR)
		tag = 'e';
	else
		return;
	if (c->truncated || len == 0)
		return;
	room = QPC_CHAN_BUDGET - c->bytes;
	if (QPC_CONN_BUDGET - qpc_conn_bytes < room)
		room = QPC_CONN_BUDGET - qpc_conn_bytes;
	keep = len < room ? len : (size_t)room;
	c->bytes += keep;
	qpc_conn_bytes += keep;
	while (keep > 0) {
		chunk = keep < QPC_RAW_CHUNK ? keep : QPC_RAW_CHUNK;
		qpc_emit(c, tag, data, chunk);
		data += chunk;
		keep -= chunk;
	}
	if (c->bytes >= QPC_CHAN_BUDGET || qpc_conn_bytes >= QPC_CONN_BUDGET) {
		c->truncated = 1;
		qpc_emit(c, 't', NULL, 0);
	}
}

void
qpcapture_child_setup(int log_stderr)
{
	struct stat st;

	qpc_fd = -1;
	if (!log_stderr || fstat(STDERR_FILENO, &st) == -1 ||
	    !S_ISFIFO(st.st_mode))
		return;
	qpc_fd = STDERR_FILENO;
}

void
qpcapture_drop(void)
{
	qpc_fd = -1;
}

void
qpcapture_session_init(void)
{
	u_char rnd[16];
	size_t i;

	if (qpc_fd == -1)
		return;
#if defined(HAVE_PRCTL) && defined(PR_SET_DUMPABLE)
	(void)prctl(PR_SET_DUMPABLE, 0);
#endif
	arc4random_buf(rnd, sizeof(rnd));
	for (i = 0; i < sizeof(rnd); i++)
		snprintf(qpc_conn + i * 2, 3, "%02x", rnd[i]);
	explicit_bzero(rnd, sizeof(rnd));
	channel_data_observer = qpc_observe;
}

void
qpcapture_open(struct ssh *ssh, int chanid, const struct passwd *pw,
    const char *command, int pty, int subsystem)
{
	struct qpc_chan *c = NULL;
	struct timespec wall;
	char host[256];
	size_t len, off, chunk;
	int i;

	if (qpc_fd == -1 || pw == NULL)
		return;
	if ((c = qpc_find(chanid)) == NULL) {
		for (i = 0; i < QPC_MAX_CHANS && c == NULL; i++)
			if (!qpc_chans[i].used)
				c = &qpc_chans[i];
		if (c == NULL)
			return;
	}
	memset(c, 0, sizeof(*c));
	c->used = 1;
	c->id = chanid;
	monotime_ts(&c->start);
	clock_gettime(CLOCK_REALTIME, &wall);
	/* The command goes first: the open record completes the start. */
	len = command == NULL ? 0 : strlen(command);
	for (off = 0; off < len && off < QPC_COMMAND_MAX; off += chunk) {
		chunk = len - off;
		if (chunk > QPC_RAW_CHUNK)
			chunk = QPC_RAW_CHUNK;
		if (off + chunk > QPC_COMMAND_MAX)
			chunk = QPC_COMMAND_MAX - off;
		qpc_emit(c, 'c', (const u_char *)command + off, chunk);
	}
	if (len > QPC_COMMAND_MAX)
		qpc_emit(c, 'C', NULL, 0);
	if (gethostname(host, sizeof(host)) == -1)
		host[0] = '\0';
	host[sizeof(host) - 1] = '\0';
	qpc_emit_text(c, 'o', "time=%lld uid=%u pty=%d sub=%d cmd=%d "
	    "rport=%d lport=%d rip=%s host=%s user=%s",
	    (long long)wall.tv_sec * 1000 + wall.tv_nsec / 1000000,
	    (u_int)pw->pw_uid, pty ? 1 : 0, subsystem ? 1 : 0,
	    command == NULL ? 0 : 1,
	    ssh_remote_port(ssh), ssh_local_port(ssh),
	    ssh_remote_ipaddr(ssh), host, pw->pw_name);
}

void
qpcapture_exit(int chanid, int status)
{
	struct qpc_chan *c;

	if (qpc_fd == -1 || (c = qpc_find(chanid)) == NULL)
		return;
	if (WIFEXITED(status))
		qpc_emit_text(c, 'x', "exit=%d", WEXITSTATUS(status));
	else if (WIFSIGNALED(status))
		qpc_emit_text(c, 'x', "signal=%d", WTERMSIG(status));
}
