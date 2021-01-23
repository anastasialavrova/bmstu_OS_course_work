#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/types.h>
#include <net/tcp.h>
#include <net/tcp_states.h>
#include <net/udp.h>

#include <net/net_namespace.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Anastasia Lavrova");
MODULE_DESCRIPTION("Support for /proc/net/tcpstat, /proc/net/tcp6stat, /proc/net/udpstat, /proc/net/udp6stat");


static const char *const tcp_state_names[] = {
		"NONE",
		"ESTB",
		"SYNS",
		"SYNR",
		"FNW1",
		"FNW2",
		"TIMW",
		"CLSD",
		"CLSW",
		"LACK",
		"LSTN",
		"CLSG",
		"SYNR"
};

static void sock_common_options_show(struct seq_file *seq, struct sock *sk) {
	if (sk->sk_userlocks & SOCK_RCVBUF_LOCK) {
		seq_printf(seq, ",SO_RCVBUF=%d", sk->sk_rcvbuf / 2);
	}
	if (sk->sk_userlocks & SOCK_SNDBUF_LOCK) {
		seq_printf(seq, ",SO_SNDBUF=%d", sk->sk_sndbuf / 2);
	}

	if (sk->sk_rcvtimeo != MAX_SCHEDULE_TIMEOUT) {
		seq_printf(seq, ",SO_RCVTIMEO=%ldms", sk->sk_rcvtimeo*1000/HZ);
	}
	if (sk->sk_sndtimeo != MAX_SCHEDULE_TIMEOUT) {
		seq_printf(seq, ",SO_SNDTIMEO=%ldms", sk->sk_sndtimeo*1000/HZ);
	}

	if (sock_flag(sk, SOCK_LINGER)) {
		seq_printf(seq, ",SO_LINGER=%lds", sk->sk_lingertime / HZ);
	}
}

static void addr_port_show(struct seq_file *seq, sa_family_t family, const void* addr, __u16 port) {
	seq_setwidth(seq, 23);
	seq_printf(seq, family == AF_INET6 ? "%pI6c" : "%pI4", addr);
	if (port == 0) {
		seq_puts(seq, ":*");
	} else {
		seq_printf(seq, ":%d", port);
	}
	seq_pad(seq, ' ');
}

static int tcp_seq_show(struct seq_file *seq, void *v) {
	if (v == SEQ_START_TOKEN) {
		seq_printf(seq, "Recv-Q Send-Q Local Address           Foreign Address         Stat Options\n");
	} else {
		struct tcp_iter_state *st = seq->private;

		struct tcp_seq_afinfo *afinfo = PDE_DATA(file_inode(seq->file));
		sa_family_t family = afinfo->family;

		int rx_queue;
		int tx_queue;
		const void *dest;
		const void *src;
		__u16 destp;
		__u16 srcp;
		int state;
		struct sock *sk;
		int fo_qlen = 0;
		u8 defer = 0;

		switch (st->state) {
			case TCP_SEQ_STATE_LISTENING:
			case TCP_SEQ_STATE_ESTABLISHED: {
				sk = v;
				if (sk->sk_state == TCP_TIME_WAIT) {
					const struct inet_timewait_sock *tw = v;

					rx_queue = 0;
					tx_queue = 0;
					if (family == AF_INET6) {
						dest = &tw->tw_v6_daddr;
						src = &tw->tw_v6_rcv_saddr;
					} else {
						dest = &tw->tw_daddr;
						src = &tw->tw_rcv_saddr;
					}
					destp = ntohs(tw->tw_dport);
					srcp = ntohs(tw->tw_sport);
					state = tw->tw_substate;
					sk = NULL;
				} else {
					const struct tcp_sock *tp;
					const struct inet_sock *inet;
					const struct fastopen_queue *fq;

					tp = tcp_sk(sk);
					inet = inet_sk(sk);
					defer = inet_csk(sk)->icsk_accept_queue.rskq_defer_accept;

					switch (sk->sk_state) {
						case TCP_LISTEN:
							rx_queue = sk->sk_ack_backlog;
							tx_queue = 0;
							fq = &inet_csk(sk)->icsk_accept_queue.fastopenq;
							if (fq != NULL) {
								fo_qlen = fq->max_qlen;
							}
							break;
						default:
							rx_queue = max_t(int, tp->rcv_nxt - tp->copied_seq, 0);
							tx_queue = tp->write_seq - tp->snd_una;
					}
					if (family == AF_INET6) {
						dest = &sk->sk_v6_daddr;
						src = &sk->sk_v6_rcv_saddr;
					} else {
						dest = &inet->inet_daddr;
						src = &inet->inet_rcv_saddr;
					}
					destp = ntohs(inet->inet_dport);
					srcp = ntohs(inet->inet_sport);
					state = sk->sk_state;
				}
				break;
			}
			default:
				return 0;
		}

		if (state < 0 || state >= TCP_MAX_STATES) {
			state = 0;
		}

		seq_printf(seq, "%6d %6d ", rx_queue, tx_queue);
		addr_port_show(seq, family, src, srcp);
		addr_port_show(seq, family, dest, destp);

		seq_printf(seq, "%s ", tcp_state_names[state]);
		if (sk != NULL) {
			seq_printf(seq, "SO_REUSEADDR=%d,SO_REUSEPORT=%d,SO_KEEPALIVE=%d", sk->sk_reuse, sk->sk_reuseport, sock_flag(sk, SOCK_KEEPOPEN));
                        if (tcp_sk(sk)->keepalive_time > 0) {
                                seq_printf(seq, ",TCP_KEEPIDLE=%u", tcp_sk(sk)->keepalive_time/HZ);
                        }
                        if (tcp_sk(sk)->keepalive_probes > 0) {
                                seq_printf(seq, ",TCP_KEEPCNT=%u", tcp_sk(sk)->keepalive_probes);
                        }
                        if (tcp_sk(sk)->keepalive_intvl > 0) {
                                seq_printf(seq, ",TCP_KEEPINTVL=%u", tcp_sk(sk)->keepalive_intvl/HZ);
                        }

			sock_common_options_show(seq, sk);

			seq_printf(seq, ",TCP_NODELAY=%d", !!(tcp_sk(sk)->nonagle&TCP_NAGLE_OFF));

			if (state == TCP_LISTEN) {
				seq_printf(seq, ",TCP_FASTOPEN=%d", fo_qlen);
			}

			seq_printf(seq, ",TCP_DEFER_ACCEPT=%d", defer);

		}
		seq_printf(seq, "\n");
	}
	return 0;
}

static const struct seq_operations tcpstat_seq_ops = {
	.show		= tcp_seq_show,
	.start		= tcp_seq_start,
	.next		= tcp_seq_next,
	.stop		= tcp_seq_stop,
};

static struct tcp_seq_afinfo tcpstat_seq_afinfo = {
	.family		= AF_INET,
};

static const struct seq_operations tcp6stat_seq_ops = {
	.show		= tcp_seq_show,
	.start		= tcp_seq_start,
	.next		= tcp_seq_next,
	.stop		= tcp_seq_stop,
};

static struct tcp_seq_afinfo tcp6stat_seq_afinfo = {
	.family		= AF_INET6,
};

static int udp_seq_show(struct seq_file *seq, void *v) {
	if (v == SEQ_START_TOKEN) {
		seq_printf(seq, "Recv-Q Send-Q Local Address           Foreign Address         Options\n");
	} else {
		struct udp_seq_afinfo *afinfo = PDE_DATA(file_inode(seq->file));
		sa_family_t family = afinfo->family;
		struct sock *sk = v;
		int tx_queue = sk_wmem_alloc_get(sk);
		int rx_queue = sk_rmem_alloc_get(sk);
		struct inet_sock *inet = inet_sk(sk);
		const void *dest;
		const void *src;
		__u16 destp;
		__u16 srcp;

		if (family == AF_INET6) {
			dest = &sk->sk_v6_daddr;
			src = &sk->sk_v6_rcv_saddr;
		} else {
			dest = &inet->inet_daddr;
			src = &inet->inet_rcv_saddr;
		}
		destp = ntohs(inet->inet_dport);
		srcp = ntohs(inet->inet_sport);

		seq_printf(seq, "%6d %6d ", rx_queue, tx_queue);
		addr_port_show(seq, family, src, srcp);
		addr_port_show(seq, family, dest, destp);

		seq_printf(seq, "SO_REUSEADDR=%d,SO_REUSEPORT=%d", sk->sk_reuse, sk->sk_reuseport);

		sock_common_options_show(seq, sk);

		seq_printf(seq, ",SO_BROADCAST=%d", sock_flag(sk, SOCK_BROADCAST));

		seq_printf(seq, "\n");
	}
	return 0;
}

static const struct seq_operations udpstat_seq_ops = {
	.start		= udp_seq_start,
	.next		= udp_seq_next,
	.stop		= udp_seq_stop,
	.show		= udp_seq_show,
};

static struct udp_seq_afinfo udpstat_seq_afinfo = {
	.family		= AF_INET,
	.udp_table	= &udp_table,
};

static const struct seq_operations udp6stat_seq_ops = {
	.start		= udp_seq_start,
	.next		= udp_seq_next,
	.stop		= udp_seq_stop,
	.show		= udp_seq_show,
};

static struct udp_seq_afinfo udp6stat_seq_afinfo = {
	.family		= AF_INET6,
	.udp_table	= &udp_table,
};

static int __net_init knetstat_net_init(struct net *net) {
	if (!proc_create_net_data("tcpstat", 0444, net->proc_net, &tcpstat_seq_ops,
			sizeof(struct tcp_iter_state), &tcpstat_seq_afinfo))
        return -ENOMEM;

	if (!proc_create_net_data("tcp6stat", 0444, net->proc_net, &tcp6stat_seq_ops,
			sizeof(struct tcp_iter_state), &tcp6stat_seq_afinfo))
        remove_proc_entry("udpstat", net->proc_net);

	if (!proc_create_net_data("udpstat", 0444, net->proc_net, &udpstat_seq_ops,
			sizeof(struct udp_iter_state), &udpstat_seq_afinfo))
        remove_proc_entry("tcp6stat", net->proc_net);

	if (!proc_create_net_data("udp6stat", 0444, net->proc_net, &udp6stat_seq_ops,
			sizeof(struct udp_iter_state), &udp6stat_seq_afinfo))
        remove_proc_entry("tcpstat", net->proc_net);

	return 0;
}

static void __net_exit knetstat_net_exit(struct net *net) {
	remove_proc_entry("tcpstat", net->proc_net);
	remove_proc_entry("tcp6stat", net->proc_net);
	remove_proc_entry("udpstat", net->proc_net);
	remove_proc_entry("udp6stat", net->proc_net);
}

static struct pernet_operations knetstat_net_ops = { .init = knetstat_net_init,
		.exit = knetstat_net_exit, };

static int knetstat_init(void) {
	int err;

	err = register_pernet_subsys(&knetstat_net_ops);
	if (err < 0)
		return err;

	return 0;
}

static void knetstat_exit(void) {
	unregister_pernet_subsys(&knetstat_net_ops);
}

module_init(knetstat_init)
module_exit(knetstat_exit)

