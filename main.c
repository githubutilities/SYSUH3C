#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <time.h>

#include <pcap/pcap.h>
#include <net/ethernet.h>

/* 802.1X报文结构 */
typedef enum { REQUEST=1, RESPONSE=2, SUCCESS=3, FAILURE=4, H3CDATA=10} EAP_CODE;
typedef enum { IDENTITY=1, NOTIFICATION=2, MD5=4, AVAILIABLE=20 } EAP_TYPE;
typedef uint8_t EAP_ID;

const uint8_t MY_MAC[6] = {0x00, 0xe0, 0x4c, 0x01, 0x10, 0x79};
const char* USERNAME = "username";
const char* PASSWORD = "password";
const char* DEVICE_NAME = "en4";

const uint8_t BROADCAST_ADDR[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
const uint8_t MULTICAST_ADDR[6] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x03};
const int DEFAULT_TIMEOUT = 1000;

void server_forever(const char *device_name);
void dispatch_request(pcap_t *handle, uint8_t ethhdr[14], const uint8_t *captured);
int send_start_pkt(pcap_t *handle, const uint8_t mac[6]);
int send_logoff_pkt(pcap_t *handle, const uint8_t mac[6]);
int response_identity(pcap_t *handle, 
	const uint8_t ethhdr[14], 
	const uint8_t *request, 
	const char *username);
int response_md5(pcap_t *handle, 
	uint8_t ethhdr[14],
	const uint8_t *request,
	const char *username,
	const char *password);

void debug_print(const uint8_t *arr, int size) {
	for (int j = 0; j < size; j++) {
		if (j % 8 == 0) putchar('\t');
		if (j % 16 == 0) putchar('\n');
		printf("%.2x ", arr[j]);
	}
	putchar('\n'); fflush(stdout);
}

int main(int argc, char const *argv[]) {
	server_forever(DEVICE_NAME);
	return 0;
}

void server_forever(const char *device_name) {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	struct bpf_program fcode;
	const uint8_t *mac = MY_MAC;
	char filter_str[100];
	const uint8_t *captured;

	handle = pcap_open_live(device_name, 65536, 1, DEFAULT_TIMEOUT, errbuf);

	sprintf(filter_str, "(ether proto 0x888e) and (ether dst host %02x:%02x:%02x:%02x:%02x:%02x)",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	pcap_compile(handle, &fcode, filter_str, 1, 0xff);
	pcap_setfilter(handle, &fcode);

	{
		struct pcap_pkthdr *header;
		bool logoff = false;
		send_start_pkt(handle, mac);
		while (1) {
			int ret = pcap_next_ex(handle, &header, &captured);
			// debug_print(captured, 24);
			if (ret == 1 && (EAP_CODE)captured[18] == REQUEST) {
				break;
			}
		}

		uint8_t ethhdr[14] = {0}; // ethernet frame header
		uint8_t dst_mac[6];
		memcpy(dst_mac + 0, captured + 6, 6);
		memcpy(ethhdr + 0, captured + 6, 6);
		memcpy(ethhdr + 6, mac, 6);
		ethhdr[12] = 0x88;
		ethhdr[13] = 0x8e; // EAP

		sprintf(filter_str, "(ether proto 0x888e) and (ether src host %02x:%02x:%02x:%02x:%02x:%02x)",
			dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]);
		pcap_compile(handle, &fcode, filter_str, 1, 0xff);
		pcap_setfilter(handle, &fcode);
		fprintf(stdout, "Server MAC is %02x:%02x:%02x:%02x:%02x:%02x\n",
                dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]);

		// send start package again
		send_start_pkt(handle, mac);

		clock_t pre_time = 0;
		clock_t cur_time = 0;
		clock_t elapsed = 0;
		int cnt = 0;
		while (!logoff) {
			int loop_cnt = 0;
			while (pcap_next_ex(handle, &header, &captured) != 1) {
				fprintf(stdout, ".");
				fflush(stdout);
				if (loop_cnt++ > 500) break;
			}

			putchar('\n');

			cur_time = clock();
			elapsed = cur_time - pre_time;
			fprintf(stderr, "time elapsed: %lu\n", elapsed);
			pre_time = cur_time;
			cnt = (elapsed > 500) ? cnt + 1: 0;
			if (cnt > 100)
				break;


			debug_print(captured, 32);

			switch( (EAP_CODE) captured[18] ) {
				case REQUEST:
					dispatch_request(handle, ethhdr, captured);
					fprintf(stderr, "ID[%d] Server: (Request)\n", captured[19]);
					break;
				case SUCCESS:
					fprintf(stderr, "ID[%d] Server: (Success)\n", captured[19]);
					break;
				case FAILURE:
					fprintf(stderr, "ID[%d] Server: (Failure)\n", captured[19]);
					break;
				case RESPONSE:
					fprintf(stderr, "ID[%d] Server: (Response)\n", captured[19]);
					break;
				default:
					fprintf(stderr, "ID[%d] Server: (Unknown)\n", captured[19]);
			}
		}
	}
}


void dispatch_request(pcap_t *handle, uint8_t ethhdr[14], const uint8_t *captured) {
	switch ((EAP_TYPE)captured[22]) {
		int ret;
		case IDENTITY:
			fprintf(stdout, "Request Identity!\n");
			ret = response_identity(handle, ethhdr, captured, USERNAME);
			// fprintf(stdout, "response id %d bytes sent\n", ret);
			break;
		case MD5:
			fprintf(stdout, "Request MD5!\n");
			ret = response_md5(handle, ethhdr, captured, USERNAME, PASSWORD);
			break;
		default:
			fprintf(stdout, "Default!\n");
			break;
	}
}

// returns the number of bytes written on success and -1 on failure.
int send_start_pkt(pcap_t *handle, const uint8_t mac[6]) {
	uint8_t packet[18];
	memcpy(packet + 6, mac, 6);
	packet[12] = 0x88;
	packet[13] = 0x8e; // EAP

	packet[14] = 0x01; // 802.1X Version=1
	packet[15] = 0x01; // Type=1 Start
	packet[16] = packet[17] = 0x00; // length=0x0000

	memcpy(packet, MULTICAST_ADDR, 6);
	int ret = pcap_inject(handle, packet, sizeof packet);

	return ret;
}

// returns the number of bytes written on success and -1 on failure.
int send_logoff_pkt(pcap_t *handle, const uint8_t mac[6]) {
	uint8_t packet[18];
	memcpy(packet + 0, MULTICAST_ADDR, 6);
	memcpy(packet + 6, mac, 6);
	packet[12] = 0x88;
	packet[13] = 0x8e; // EAP

	packet[14] = 0x01;				// 802.1X Version=1
	packet[15] = 0x02;				// Type = 2 Logoff
	packet[16] = packet[17] = 0x00; // Length = 0x0000

	int ret = pcap_inject(handle, packet, sizeof packet);
	return ret;
}

// returns the number of bytes written on success and -1 on failure.
int response_identity(pcap_t *handle, 
	const uint8_t ethhdr[14], 
	const uint8_t *request, 
	const char *username) {
	assert((EAP_CODE) request[18] == REQUEST);
	assert((EAP_TYPE) request[22] == IDENTITY);

	size_t i, username_len = strlen(username);
	uint8_t response[128];
	uint16_t eaplen;
	int ret;

	response[14] = 0x01; // 802.1X Version 1
	response[15] = 0x00; // Type=0 (EAP Packet)
	// response[16~17], Length

	/* Extensible Authentication Protocol */
	response[18] = (EAP_CODE) RESPONSE; //Code
	response[19] = request[19]; // ID
	// response[20~21] Length

	response[22] = (EAP_TYPE) IDENTITY; // Type
	/* Type-Data */
	uint8_t version[32] = { 0x06, 0x07, 0x59, 0x54, 0x46, 0x33, 0x52, 0x45, 0x46, 0x64, 0x59, 0x33, 0x77, 0x6c, 0x47, 0x30, 0x55, 0x36, 0x66, 0x51, 0x38, 0x75, 0x64, 0x5a, 0x6a, 0x44, 0x71, 0x72, 0x41, 0x3d, 0x20, 0x20 };
	memcpy(response + 23, version, sizeof version);
	i = 23 + sizeof version;

	memcpy(response, ethhdr, 14);
	
	memcpy(response + i, username, username_len);
	i += username_len;

	assert(i <= (sizeof response));

	eaplen = htons(i - 18);
	memcpy(response + 16, &eaplen, sizeof eaplen);
	memcpy(response + 20, &eaplen, sizeof eaplen);

	// debug_print(response, i);
	ret = pcap_inject(handle, response, i);

	return ret;
}

int response_md5(pcap_t *handle, 
	uint8_t ethhdr[14],
	const uint8_t *request,
	const char *username,
	const char *password) {
	assert((EAP_CODE)request[18] == REQUEST);
    assert((EAP_TYPE)request[22] == MD5);

    uint8_t response[128];
    uint32_t username_len;
    uint16_t eaplen;
    uint8_t md5_data[16];
    uint32_t password_len;
    uint32_t cnt;
    int ret;

    username_len = strlen(username);
    password_len = strlen(password);

    /* use multicast for responding md5 */
    memcpy(ethhdr, MULTICAST_ADDR, 6);

    memcpy(response, ethhdr, 14);

    response[14] = 0x01; // 802.1X Version 1
	response[15] = 0x00; // Type=0 (EAP Packet)
	// response[16~17], Length

	/* Extensible Authentication Protocol */
	response[18] = (EAP_CODE) RESPONSE; //Code
	response[19] = request[19]; // ID
	// response[20~21] Length

	response[22] = (EAP_TYPE) MD5;
	response[23] = 16;

	memcpy(md5_data, request + 24, 16);

	// debug_print(md5_data, 16);

	password_len = password_len > 16 ? 16: password_len;
	for (uint32_t i = 0; i < password_len; i++) {
		md5_data[i] ^= password[i];
	}
	memcpy(response + 24, md5_data, 16);

	cnt = 24 + 16;
	memcpy(response + cnt, username, username_len);
	cnt += username_len;

	eaplen = htons(cnt - 18);
	memcpy(response + 16, &eaplen, sizeof eaplen);
	memcpy(response + 20, &eaplen, sizeof eaplen);

	// debug_print(response, cnt);

	ret = pcap_inject(handle, response, cnt);

	return ret;
}