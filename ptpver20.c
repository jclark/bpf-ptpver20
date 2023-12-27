/*
This program loads and attaches a BPF TC egress filter that sets the minor version of PTP v2 packets to 0.
Currently this works only for UDP IPv4 PTP transport.
The program accepts a single argument, which is the name of the interface to attach to.
When the program receives a SIGINT (Ctrl-C), it detaches the filter and exits.

The program uses libbpf, based on the docs in the following:
https://patchwork.kernel.org/project/netdevbpf/patch/20210512103451.989420-3-memxor@gmail.com/
*/

#include "ptpver20.skel.h"

#include <stdio.h>
#include <stdbool.h>
// for if_nametoindex
#include <net/if.h>
#define __USE_POSIX 1
#include <signal.h>

static const char *prog_name;

static int run(char *ifname);
static int create_hook(struct ptpver20_bpf *skel, int ifindex);
static int attach(int fd, const struct bpf_tc_hook *hook);
static int block_signal();
static int wait_signal();
static void init_signal(sigset_t *set);
static void print_started();
static int print_err(char *s, int err);
static int print_errno(char *s);

int main(int argc, char **argv) {
	prog_name = argv[0];
	if (argc != 2) {
		fprintf(stderr, "Usage: %s <interface-name>\n", prog_name);
		return EXIT_FAILURE;
	}
	int err = run(argv[1]);
	return err < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}

static int run(char *ifname) {
	int ifindex = if_nametoindex(ifname);
	if (ifindex == 0) {
		return print_errno(ifname);
	}
	int err = block_signal();
	if (err < 0)
		return err;
	struct ptpver20_bpf *skel = ptpver20_bpf__open_and_load();
	if (!skel)
		return print_err("failed to load BPF program", -ENOMEM);
	err = create_hook(skel, ifindex);
	ptpver20_bpf__destroy(skel);
	return err;
}

static int create_hook(struct ptpver20_bpf *skel, int ifindex) {
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook,
		.ifindex = ifindex,
		.attach_point = BPF_TC_EGRESS);
	int cerr = bpf_tc_hook_create(&hook);
	// An EEXIST error may happen because the qdisc was already created by another process or user.
	// If there was also an ingress filter, then bpf_tc_hook_destroy would not remove the qdisc.
	if (cerr < 0 && cerr != -EEXIST)
		return print_err("bpf_tc_hook_create", cerr);
	int err = attach(bpf_program__fd(skel->progs.tc_egress), &hook);
	if (cerr >= 0)
		bpf_tc_hook_destroy(&hook);
	return err;
}

static int attach(int fd, const struct bpf_tc_hook *hook) {
	DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts, .prog_fd = fd);
	int err = bpf_tc_attach(hook, &opts);
	if (err < 0)
		return print_err("bpf_tc_attach", err);
	print_started();
	int serr = wait_signal();
	opts.flags = opts.prog_fd = opts.prog_id = 0;
	err = bpf_tc_detach(hook, &opts);
	if (serr < 0)
		return serr;
	if (err < 0)
		return print_err("bpf_tc_detach", err);
	return 0;
}

static int wait_signal() {
	sigset_t set;
	init_signal(&set);
	int err = sigwaitinfo(&set, NULL);
	if (err < 0) {
		if (errno == EINTR)
			return print_errno("terminating on unexpected signal");
		return print_errno("sigwaitinfo");
	}
	return 0;
}

static int block_signal() {
	sigset_t set;
    init_signal(&set);
    int err = sigprocmask(SIG_BLOCK, &set, NULL);
	if (err < 0)
		return print_errno("sigprocmask");
	return 0;
}

static void init_signal(sigset_t *set) {
	sigemptyset(set);
	sigaddset(set, SIGINT);
}

static void print_started() {
	fprintf(stderr, "%s: successfully started ptpver20 filter; use SIGINT (Ctrl-C) to stop\n", prog_name);
	fprintf(stderr, "%s: see trace in \"/sys/kernel/debug/tracing/trace_pipe\"\n", prog_name);
}

static int print_errno(char *s) {
	return print_err(s, -errno);
}

// err is a libbpf negative error number (e.g. -EINVAL)
static int print_err(char *msg, int err) {
	fprintf(stderr, "%s: %s: %s\n", prog_name, msg, strerror(-err));
	return err;
}
