#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#define SPLITTED	"splitted"
#define PKTHDR_LEN	16
#define PCAP_HDR	24

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

static void write_pcap_data(struct dump_pcap_pkthdr packet_header, unsigned char buff[])
{
	int fd = -1;
	char path[300] = {0};

	snprintf(path, 300, "%s_%d.cap", SPLITTED, file_count);

	fd = open(path, O_WRONLY | O_APPEND, S_IRUSR | S_IWUSR);
	if(fd > 0) {
		write(fd, (const void *)&packet_header, PKTHDR_LEN);
		write(fd, buff, packet_header.caplen);
		close(fd);
	}

}

static void write_pcap_header(struct dump_pcap_file_header pcap_header)
{
	int fd = -1;
	char path[300] = {0};

	snprintf(path, 300, "%s_%d.cap", SPLITTED, file_count);

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
	if(fd > 0) {
		write(fd, (const void *)&pcap_header, PCAP_HDR);
		close(fd);
	}
}

static void read_pcap_file(char *file, int split_size)
{
	int total = 0;
	int fd    = -1;
	unsigned int r      = 0;
	unsigned char buff[65535];
	int threshold = (split_size * (1000 * 1000));
	struct dump_pcap_pkthdr packet_header;
	struct dump_pcap_file_header pcap_header;

	fd = open(file, O_RDONLY);
	if(fd < 0) {
		printf("Fail open file: %s\n", file);
		return;
	}

	if(read(fd, &pcap_header, PCAP_HDR) != PCAP_HDR) {
		printf("Failed to read TCPDump Header from file: %s\n", file);
		return;
	}

	while(1)
	{
		if(total == 0)
			write_pcap_header(pcap_header);

		r = read(fd, &packet_header, PKTHDR_LEN);
		if(r != PKTHDR_LEN)
			break;

		memset(buff, '\0', pcap_header.snaplen);

		r = read(fd, &buff, packet_header.caplen);
		if(r != packet_header.caplen)
			break;

		write_pcap_data(packet_header, buff);

		total += r;

		if(total >= threshold) {
			file_count++;
			total = 0;
		}
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

	read_pcap_file(argv[1], atoi(argv[2]));

	return 0;
}
