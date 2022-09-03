#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

/* tap */
#include <sys/ioctl.h> // ioctl
#include <net/if.h> // ifreq
#include <linux/if_tun.h> // IFF_TAP
#include <fcntl.h> // open
#include <unistd.h> // close

/* socket */
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* interface */
#include <netdb.h>
#include <ifaddrs.h>
#include <linux/if_link.h>

#define SILENT_EXEC // surpress output when executing commands

/* customize your tunnel */
#define UDP_PORT 5535			// UDP port for the tunnel
#define BR_IF_NAME "br0p"		// Bridge interface name
#define SPOOF_MAC "aa:aa:aa:cc:cc:cc"	// MAC address of the client TAP

#define MTU 65507 // maximum transmission unit for the tunnel (UDP)
/* random 64 byte key for "encryption" */
#define KEY "f~Pq25GHyJieV&Y3^ScVzz-Mq@w924XMQ1OJbSXt4NMz3hbS%OnYL%hZH9zft^5h"

int create_tap(char* tap_id);
void die_with(char* msg, int code);
void execute(char* cmd);
int create_tunnel(int is_client, struct sockaddr_in* tun_addr, socklen_t* addr_len);
void configure_network(int is_client, char* tap_id);
void manage_tunnel(int tap, int udp, struct sockaddr* tun_addr, socklen_t* addr_len, int is_client);
void encrypt_tunnel(char* enc_buf, char* clear_buf, int size);
void decrypt_tunnel(char* dec_buf, char* enc_buf, int size);
int parse_if(void);
void hook_sig(void);
void cleanup(int sig);
void help_exit(char* p);
void display_config(int is_client, char* tap_id);

/* important globals - don't touch */
char UDP_TARGET[16];		// server address
char TARGET_CIDR[19];		// for tap on client, for target on server
char TARGET_ETH[IFNAMSIZ];	// target network interface name
int PROMISCUOUS_ENABLED = 1;	// default for promiscuous mode

int main(int argc, char** argv){
	int is_client = 0;

	if (argc == 1) {
		printf("Usage: %s [-c] [-p] [-h (for help)] SERVER_IP CIDR_NEW|CIDR_PIVOT\n", argv[0]);
		return 1;
	}

	int c;
	while((c = getopt(argc, argv, "chp")) != -1)
		switch(c) {
			// client mode
			case 'c':
				is_client = 1; break;
			// fake promiscuous mode
			case 'p':
				PROMISCUOUS_ENABLED = 0; break;
			// view help
			case 'h':
				help_exit(argv[0]); break;
			case '?':
				help_exit(argv[0]);
				break;
			default:
				abort();
		}
	// require at least 2 parameters
	int index = optind;
	if ( argc-index != 2)
		help_exit(argv[0]);

	// assign first parameter to udp server address
	snprintf(UDP_TARGET, sizeof(UDP_TARGET), "%s", argv[index++]);

	// use second parameter to assign cidr notation for tap or target interface
	snprintf(TARGET_CIDR, sizeof(TARGET_CIDR), "%s", argv[index]);

	// on the server we need to get the target interface name
	if (!is_client)
		if (!parse_if()) {
			fprintf(stderr, "[!] Could not find any interface that matches %s\n", TARGET_CIDR);
			return 1;
		}

	int tap;
	int udp;
	char tap_id[IFNAMSIZ];

	struct sockaddr_in tun_addr;
	socklen_t addr_len = sizeof(tun_addr);

	fprintf(stdout, "[+] Creating tap\n");
	tap = create_tap(tap_id);
	fprintf(stdout, "[>] Tap set up: %s\n", tap_id);

	fprintf(stdout, "[+] Creating tunnel\n");
	udp = create_tunnel(is_client, &tun_addr, &addr_len);
	fprintf(stdout, "[>] Sockets ready\n");

	fprintf(stdout, "[+] Configuring network\n");
	configure_network(is_client, tap_id);
	fprintf(stdout, "[>] Finished ip setup\n");

	// register cleanup routine for server
	if (!is_client)
		hook_sig();

	display_config(is_client, tap_id);

	fprintf(stdout, "[+] Starting tunnel...\n");
	manage_tunnel(tap, udp, (struct sockaddr*)&tun_addr, &addr_len, is_client);

	return EXIT_SUCCESS;
}

/* setup UDP tunnel for connection between client and server */
int create_tunnel(int is_client, struct sockaddr_in* tun_addr, socklen_t* addr_len) {
	int udp_fd, flags;

	memset(tun_addr, 0, *addr_len);

	tun_addr->sin_family = AF_INET;

	if (!inet_aton(UDP_TARGET, &tun_addr->sin_addr))
		die_with("Invalid udp server address", EXIT_FAILURE);

	tun_addr->sin_port = htons(UDP_PORT);

	if ((udp_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0 )
		die_with("Creating udp socket failed", udp_fd);

	if (!is_client)
		if (bind(udp_fd, (struct sockaddr*)tun_addr, *addr_len) < 0)
			die_with("Binding udp server failed", EXIT_FAILURE);

	flags = fcntl(udp_fd, F_GETFL, 0);
	if (flags < 0 || fcntl(udp_fd, F_SETFL, flags | O_NONBLOCK) < 0)
		die_with("Failed to set socket flag O_NONBLOCK", EXIT_FAILURE);

	return udp_fd;
}

/* configure interfaces */
void configure_network(int is_client, char* tap_id) {
	char cmd[2048];

	// activate tap
	snprintf(cmd, sizeof(cmd), "ip link set %s up", tap_id);
	execute(cmd);

	// Client
	if (is_client) {
		// assign ip to tap
		snprintf(cmd, sizeof(cmd), "ip addr add %s dev %s", TARGET_CIDR, tap_id);
		execute(cmd);

		// assign mac to tap
		snprintf(cmd, sizeof(cmd), "ip link set address %s dev %s", SPOOF_MAC, tap_id);
		execute(cmd);

	// Server
	} else {
		// create a bridge
		snprintf(cmd, sizeof(cmd), "ip link add %s type bridge", BR_IF_NAME);
		execute(cmd);

		// add tap to bridge
		snprintf(cmd, sizeof(cmd), "ip link set %s master %s", tap_id, BR_IF_NAME);
		execute(cmd);

		// take target ethernet adapter down
		snprintf(cmd, sizeof(cmd), "ip link set dev %s down", TARGET_ETH);
		execute(cmd);

		// flush ip addr of ethernet adapter
		snprintf(cmd, sizeof(cmd), "ip addr flush dev %s", TARGET_ETH);
		execute(cmd);

		// bring eth back up again
		snprintf(cmd, sizeof(cmd), "ip link set dev %s up", TARGET_ETH);
		execute(cmd);

		// set interface to promiscuous mode
		// keep in mind that the NIC must support this mode
		// and that the promiscuous mode may be controlled by the hypervisor in a virtual environment
		if (PROMISCUOUS_ENABLED) {
			snprintf(cmd, sizeof(cmd), "ip link set dev %s promisc on", TARGET_ETH);
			execute(cmd);
		}

		// add eth to bridge
		snprintf(cmd, sizeof(cmd), "ip link set %s master %s", TARGET_ETH, BR_IF_NAME);
		execute(cmd);

		// bring bridge up
		snprintf(cmd, sizeof(cmd), "ip link set dev %s up", BR_IF_NAME);
		execute(cmd);

		// assign ip address
		snprintf(cmd, sizeof(cmd), "ip addr add %s dev %s", TARGET_CIDR,  BR_IF_NAME);
		execute(cmd);

		if (!PROMISCUOUS_ENABLED) {
			// set up NAT for MAC
			// towards the target network
			snprintf(cmd, sizeof(cmd), "ebtables -t nat -A POSTROUTING -o %s -j snat --snat-arp --to-src $(cat /sys/class/net/%s/address)", TARGET_ETH, TARGET_ETH);
			execute(cmd);

			// from the target network
			// (!) since this will forward *everything* from the target network the target network cannot access the server itself anymore
			snprintf(cmd, sizeof(cmd), "ebtables -t nat -A PREROUTING -i %s -j dnat --to-destination %s", TARGET_ETH, SPOOF_MAC);
			execute(cmd);
		}
	}
}


/* revert any changes */
void cleanup(int sig) {

	fprintf(stdout, "[+] (%i) Shutting down...\n", sig);
	char cmd[2048];

	// the tap will be deleted automatically

	// bring bridge down
	snprintf(cmd, sizeof(cmd), "ip link set %s down", BR_IF_NAME);
	execute(cmd);

	// delete bridge
	snprintf(cmd, sizeof(cmd), "ip link delete %s", BR_IF_NAME);
	execute(cmd);

	// restore target eth
	snprintf(cmd, sizeof(cmd), "ip addr add %s dev %s", TARGET_CIDR, TARGET_ETH);
	execute(cmd);

	if (!PROMISCUOUS_ENABLED) {
		// delete mac nat
		snprintf(cmd, sizeof(cmd), "ebtables -t nat -D POSTROUTING -o %s -j snat --snat-arp --to-src $(cat /sys/class/net/%s/address)", TARGET_ETH, TARGET_ETH);
		execute(cmd);

		snprintf(cmd, sizeof(cmd), "ebtables -t nat -D PREROUTING -i %s -j dnat --to-destination %s", TARGET_ETH, SPOOF_MAC);
		execute(cmd);
	}
	exit(EXIT_SUCCESS);
}

/* start loop (forward packets from local wire to remote partner and vice versa) */
void manage_tunnel(int tap, int udp, struct sockaddr* tun_addr, socklen_t* addr_len, int is_client) {
	char tap_buf[MTU];
	char udp_buf[MTU];
	memset(tap_buf, 0, sizeof(tap_buf));
	memset(udp_buf, 0, sizeof(udp_buf));

	// prepare the mac address as byte array in case of rewriting arp replies
	unsigned char mac[6];
	sscanf(SPOOF_MAC, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);

	fd_set readset, origset;
	FD_ZERO(&origset);
	FD_SET(tap, &origset);
	FD_SET(udp, &origset);

	int maxfd = (tap > udp ? tap : udp);

	for (;;) {
		readset = origset;
		if (select(maxfd+1, &readset, NULL, NULL, NULL) < 0)
			die_with("select failed", EXIT_FAILURE);

		int n;

		/* read data from the wire and send it via udp */
		if FD_ISSET(tap, &readset) {
			if ((n = read(tap, tap_buf, MTU)) < 0)
				die_with("Tap read error", n);

			//fprintf(stdout, "# [TAP] received %i bytes ---> send to [UDP]\n", n);

			// Check if the incoming packet is an arp reply (if we are server and faking promisc)
			if (n==60 && !is_client && !PROMISCUOUS_ENABLED)
				// make sure to only modify arp replies (bytes 12,13 -> type: ARP, bytes 20,21 -> opcode: reply)
				if (tap_buf[0xc] == 8 && tap_buf[0xd] == 6 && tap_buf[0x14] == 0 && tap_buf[0x15] == 2)
					// rewrite mac address to spoofed mac of client
					memcpy(tap_buf+0x20, mac, 6);

			encrypt_tunnel(udp_buf, tap_buf, n);

			if (sendto(udp, udp_buf, n, 0, tun_addr, *addr_len) != n)
				die_with("Udp send error", EXIT_FAILURE);
		}

		/* read data from udp and write it to the local wire */
		if FD_ISSET(udp, &readset) {
			if ((n = recvfrom(udp, udp_buf, MTU, 0, tun_addr, addr_len)) < 0)
				die_with("Udp recvfrom error", n);

			//fprintf(stdout, "# [UDP] received %i bytes ---> send to [TAP]\n", n);
			decrypt_tunnel(tap_buf, udp_buf, n);

			if (write(tap, tap_buf, n) < 0)
				die_with("Tap write error", EXIT_FAILURE);
		}
	}
}

/* encrypt the UDP channel */
void encrypt_tunnel(char* enc_buf, char* clear_buf, int size) {
	// this is just a simple XOR - it's trivial to decrypt
	// if you care about confidentiality you should change this
	while (size--)
		*enc_buf++ = *clear_buf++ ^ KEY[size%64];
}

/* decrypt the UDP channel */
void decrypt_tunnel(char* dec_buf, char* enc_buf, int size) {
	// this is just a simple XOR
	// reverse of the `encrypt_tunnel` function
	while (size--)
		*dec_buf++ = *enc_buf++ ^ KEY[size%64];
}

/* create a tap interface */
int create_tap(char* tap_id) {
	struct ifreq ifr;
	int tap_fd, err;

	if ((tap_fd = open("/dev/net/tun", O_RDWR)) < 0)
		die_with("Failed to open /dev/net/tun", EXIT_FAILURE);

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

	if ((err = ioctl(tap_fd, TUNSETIFF, (void*)&ifr)) < 0)
		die_with("Failed to setup tap (ioctl)", err);

	strcpy(tap_id, ifr.ifr_name);
	return tap_fd;
}

/* parse the TARGET_CIDR to get the corresponding interface name */
int parse_if(void) {
	int if_found = 0;

	char cidr[19];
	strcpy(cidr, TARGET_CIDR);
	char *target_host = strtok(cidr, "/");

	/* following the example from: https://man7.org/linux/man-pages/man3/getifaddrs.3.html */
	struct ifaddrs *ifaddr;
	int family, s;
	char host[NI_MAXHOST];

	if (getifaddrs(&ifaddr) == -1)
		die_with("getifaddrs", EXIT_FAILURE);

	for (struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL)
			continue;
		family = ifa->ifa_addr->sa_family;


		if (family != AF_INET)
			continue;

		s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
		if (s != 0) {
			fprintf(stderr, "[!] getnameinfo() failed: %s\n", gai_strerror(s));
			exit(EXIT_FAILURE);
		}
		if (strcmp(host, target_host) != 0)
			continue;
		if_found = 1;

		snprintf(TARGET_ETH, sizeof(TARGET_ETH), "%s", ifa->ifa_name);
		break;
	}

	freeifaddrs(ifaddr);

	return if_found;
}

void execute(char* cmd) {
#ifndef SILENT_EXEC
	fprintf(stdout, "[-] Executing `%s`\n", cmd);
#endif
	int err = system(cmd);
	if (err) {die_with(cmd, err);}
}

void die_with(char* msg, int code) {
	perror(msg);
	exit(code);
}

void hook_sig(void) {
	struct sigaction sa;
	sa.sa_handler = &cleanup;
	sigfillset(&sa.sa_mask);

	if (sigaction(SIGHUP, &sa, NULL) || sigaction(SIGINT, &sa, NULL) || sigaction(SIGTERM, &sa, NULL))
		die_with("Failed to process signal", EXIT_FAILURE);
}

void help_exit(char* p) {
	printf("Usage: %s [-c] [-p] [-h] SERVER_IP CIDR_NEW|CIDR_PIVOT\n", p);
	printf("\n");
	printf("          -h:  view this help message\n");
	printf("          -c:  run as client (requires CIDR_NEW)\n");
	printf("               (if not specified run as server (requires CIDR_PIVOT))\n");
	printf("          -p:  fake promiscuous mode (think of NAT but for MAC)\n");
	printf("               (only applies on server, see `Notes` for more details)\n");
	printf("   SERVER_IP:  the ip address of the interface on the server that will be used for the tunnel\n");
	printf("    CIDR_NEW:  the new ip address on the client (including the subnet mask in CIDR notation)\n");
	printf("               (the netmask must match the target network and you should choose an available IP address)\n");
	printf("  CIDR_PIVOT:  the ip address of the interface to pivot to (including the subnet mask in CIDR notation)\n");
	printf("\n");
	printf("Example:\n");
	printf(" (Client: 10.0.0.1)      (Server: 10.0.0.2 & 172.16.0.2)      (Target: 172.16.0.1)\n");
	printf("\n");
	printf("         Server# %s [-p] 10.0.0.2 172.16.0.2/24\n", p);
	printf("         Client# %s -c 10.0.0.2 172.16.0.3/24\n", p);
	printf("\n");
	printf(" ==> (Client: 10.0.0.1 & 172.16.0.3)\n");
	printf("\n");
	printf("Notes:\n");
	printf("  If the server is unable to capture traffic that's meant for the client (i.e. no promiscuous\n");
	printf("  mode available), you can use `-p` to masquerade/forward all traffic.\n");
	printf("  \n");
	printf("  Careful, everything coming from the target network will be forwarded to the client.\n");
	printf("  This will render the server unreachable from the target network.\n");
	printf("\n");
	exit(EXIT_FAILURE);
}

void display_config(int is_client, char* tap_id) {
	printf("-------------------------------------------\n");
	printf("[CONFIG]\n");
	printf("    mode              : %s\n", (is_client?"CLIENT": "SERVER"));
	printf("    tap interface     : %s\n", tap_id);
	if (is_client) {
		printf("    tap mac address   : %s\n", SPOOF_MAC);
		printf("    tunneling via     : %s:%i\n", UDP_TARGET, UDP_PORT);
		printf("    tap ip address    : %.*s\n", (int) strcspn(TARGET_CIDR, "/"), TARGET_CIDR);
	} else {
		printf("    promiscuous mode  : %s\n", (PROMISCUOUS_ENABLED ? "enabled" : "disabled (faking it)"));
		printf("    serving tunnel on : %s:%i\n", UDP_TARGET, UDP_PORT);
		printf("    target network    : %s (%s)\n", TARGET_CIDR, TARGET_ETH);
	}
	printf("-------------------------------------------\n");
}
