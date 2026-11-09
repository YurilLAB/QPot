/* Session plaintext capture for a disposable honeypot backend. */

#ifndef QPCAPTURE_H
#define QPCAPTURE_H

struct ssh;
struct passwd;

void	qpcapture_child_setup(int);
void	qpcapture_drop(void);
void	qpcapture_session_init(void);
void	qpcapture_open(struct ssh *, int, const struct passwd *, const char *,
	    int, int);
void	qpcapture_exit(int, int);

#endif
