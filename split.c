#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

static int file_count = 0;

struct dump_pcap_pkthdr {
	struct          timeval ts;
	unsigned int    caplen;
	unsigned int    len;
};

struct dump_pcap_file_header {
	unsigned int    magic;
	unsigned short  version_major;
	unsigned short  version_minor;
	int             thiszone;
	unsigned int    sigfigs;
	unsigned int    snaplen;
	unsigned int    linktype;
};

static void write_pcap_header(struct dump_pcap_file_header pcap_header)
{
}

static void read_pcap_file(char *file, int split_size)
{
	int r     = 0;
	int tot_r = 0;
	int fd    = -1;
	unsigned char *buff = NULL;
	int reach = (split_size * (1024 * 1024));
	struct dump_pcap_pkthdr packet_header    = {0};
	struct dump_pcap_file_header pcap_header = {0};

	fd = open(file, O_RDONLY);
	if(fd < 0) {
		printf("Fail open file: %s\n", file);
		return;
	}

	if(read(fd, &pcap_header, sizeof(pcap_header)) != sizeof(pcap_header)) {
		printf("Failed to read TCPDump Header from file: %s\n", file);
		return;
	}

	write_pcap_header(pcap_header);

	buff = malloc(pcap_header.snaplen);

	while(1)
	{
		r = read(fd, &packet_header, sizeof(packet_header));
		if(r != sizeof(packet_header))
			break;

		tot_r += r;

		if(tot_r >= split_size) {
			//no
		}

		//lseek(fd, packet_header.caplen, SEEK_CUR);
	}

	close(fd);
}

int main(int argc, char **argv)
{
	if(argc != 3) {
		printf("Use: %s <file to split> <size in MB>\n", argv[0]);
		return 1;
	}

	if(access(argv[1], R_OK) != 0) {
		printf("Fail access: %s\n", argv[1]);
		return 1;
	}

	read_pcap_file(argv[1], 10);

	return 0;
}
