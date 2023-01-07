/*
 * pcapng_parser
 * 
 * (C) 2022 - Emanuele Faranda
 *
 * https://datatracker.ietf.org/doc/draft-tuexen-opsawg-pcapng
 */

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <inttypes.h>

/* ******************************************************* */

/* Block types */
#define BLOCK_TYPE_IDB 0x00000001 /* Interface Description Block */
#define BLOCK_TYPE_PB  0x00000002 /* Packet Block (obsolete) */
#define BLOCK_TYPE_SPB 0x00000003 /* Simple Packet Block */
#define BLOCK_TYPE_NRB 0x00000004 /* Name Resolution Block */
#define BLOCK_TYPE_ISB 0x00000005 /* Interface Statistics Block */
#define BLOCK_TYPE_EPB 0x00000006 /* Enhanced Packet Block */
#define BLOCK_TYPE_DSB 0x0000000A /* Decryption Secrets Block */
#define BLOCK_TYPE_SHB 0x0A0D0D0A /* Section Header Block */

/* Secrets types */
#define DSB_TYPE_TLS_KEYLOG 	0x544c534b
#define DSB_TYPE_WIREGUARD_KEY	0x57474b4c

#define SHB_MAGIC 0x1A2B3C4D

/* ******************************************************* */

// 3.1.  General Block Structure
typedef struct pcapng_block_hdr {
	uint32_t type;
	uint32_t total_length;
	// uint8_t *body;  						// variable length, padded to 32 bits
	// uint32_t total_length_2; 			// duplicated, to allow backward navigation
} __attribute__((packed)) pcapng_block_hdr_t;

typedef struct pcapng_block_opt {
	uint16_t type;
	uint16_t length;
	/* ..opt_value.. */						// padded to 32 bits
} __attribute__((packed)) pcapng_block_opt_t;

typedef struct pcapng_section_block_hdr {
	uint32_t magic;
	uint16_t version_major;
	uint16_t version_minor;
	uint64_t section_length; 				// might be -1 for unknown
	/* ..options.. */
} __attribute__((packed)) pcapng_section_block_hdr_t;

typedef struct pcapng_intf_descr_block {
	uint16_t linktype;
	uint16_t reserved;
	uint32_t snaplen;
	/* ..options.. */
} __attribute__((packed)) pcapng_intf_descr_block_t;

typedef struct pcapng_decr_secrets_block {
	uint32_t secrets_type;
	uint32_t secrets_length;
	/* ..secrets data.. */
	/* ..options.. */
} __attribute__((packed)) pcapng_decr_secrets_block_t;

typedef struct pcapng_enh_packet_block {
	uint32_t interface_id;
	uint32_t timestamp_high;
	uint32_t timestamp_low;
	uint32_t captured_len;
	uint32_t packet_len;
	/* ..packet data.. */
	/* ..padding.. */
	/* ..options.. */
} __attribute__((packed)) pcapng_enh_packet_block_t;

/* ******************************************************* */

#define MIN_BLOCK_SIZE (sizeof(pcapng_block_hdr_t) + 4)
#define MAX_BLOCK_SIZE (16*1024*1024)	// safety guard

static FILE *inputf = NULL;
static uint32_t snaplen = 0;
static u_char *pkt_buf = NULL;

/* ******************************************************* */

static const char* block_type_str(uint32_t tp) {
	switch(tp) {
		case BLOCK_TYPE_IDB:	return "Interface Description Block";
		case BLOCK_TYPE_PB:		return "Packet Block";
		case BLOCK_TYPE_SPB:	return "Simple Packet Block";
		case BLOCK_TYPE_NRB:	return "Name Resolution Block";
		case BLOCK_TYPE_ISB:	return "Interface Statistics Block";
		case BLOCK_TYPE_EPB:	return "Enhanced Packet Block";
		case BLOCK_TYPE_DSB:	return "Decryption Secrets Block";
		case BLOCK_TYPE_SHB:	return "Section Header Block";
		default:				return "Unknown Block";
	}
}

/* ******************************************************* */

// https://www.tcpdump.org/linktypes.html
static const char* linktype_str(uint32_t linktype) {
	switch(linktype) {
		case 0:			return "null";
		case 1:			return "ethernet";
		case 101:		return "raw";
		case 113:		return "SLL";
		default:		return "unknown";
	}
}

/* ******************************************************* */

static const char* dsb_type_str(uint32_t sectype) {
	switch(sectype) {
		case DSB_TYPE_TLS_KEYLOG:		return "TLS Key Log";
		case DSB_TYPE_WIREGUARD_KEY:	return "Wireguard Key";
		default:						return "unknown";
	}
}

/* ******************************************************* */

// https://gist.github.com/ccbrown/9722406
static void hexdump(const void* data, size_t size) {
  char ascii[17];
  size_t i, j;
  ascii[16] = '\0';

  for (i = 0; i < size; ++i) {
    printf("%02x ", ((unsigned char*)data)[i]);

    if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~')
      ascii[i % 16] = ((unsigned char*)data)[i];
    else
      ascii[i % 16] = '.';
    
    if ((i+1) % 8 == 0 || i+1 == size) {
      printf(" ");

      if ((i+1) % 16 == 0)
        printf("|  %s \n", ascii);
      else if (i+1 == size) {
        ascii[(i+1) % 16] = '\0';

        if ((i+1) % 16 <= 8)
          printf(" ");

        for (j = (i+1) % 16; j < 16; ++j)
          printf("   ");

        printf("|  %s \n", ascii);
      }
    }
  }
}

/* ******************************************************* */

static uint32_t _read(void *dst, uint32_t size) {
	size_t rv = fread((u_char*) dst, size, 1, inputf);
	if(rv != 1) {
		if(feof(inputf))
			exit(0);

		fprintf(stderr, "fread failed[%d]: %s\n", errno, strerror(errno));
		exit(1);
	}
	return size;
}

static uint32_t _skip(uint32_t size) {
	if(!size)
		return 0;

	assert(fseek(inputf, size, SEEK_CUR) == 0);
	return size;
}

/* ******************************************************* */

// 4.1.  Section Header Block (mandatory)
static void read_section_header_block(uint32_t body_len) {
	pcapng_section_block_hdr_t sect_block;

	assert(body_len >= sizeof(sect_block));
	body_len -= _read(&sect_block, sizeof(sect_block));

	// TODO support different endianess
	assert(sect_block.magic == SHB_MAGIC);

	// parse options
	char *user_app = NULL;
	while(body_len >= sizeof(pcapng_block_opt_t)) {
		pcapng_block_opt_t opt;

		body_len -= _read(&opt, sizeof(pcapng_block_opt_t));
		uint8_t padding = (~opt.length + 1) & 0x3;
		assert((opt.length + padding) <= body_len);

		if(opt.type == 0x4 /* shb_userappl */) {
			user_app = malloc(opt.length + 1);
			assert(user_app != NULL);
			body_len -= _read(user_app, opt.length);
			*(user_app + opt.length) = '\0';
		} else
			body_len -= _skip(opt.length + padding);
	}

	printf("  SHB v%u.%u - App: %s - Len: ", sect_block.version_major,
					sect_block.version_minor, user_app ? user_app : "");
	if(sect_block.section_length == (uint64_t)-1)
		printf("unknown\n");
	else
		printf("%" PRIu64 "\n", sect_block.section_length);

	if((sect_block.version_major != 1) || (sect_block.version_minor != 0)) {
		fprintf(stderr, "unsupported PCAPNG version\n");
		exit(1);
	}

	if(user_app)
		free(user_app);

	_skip(body_len);
}

/* ******************************************************* */

// 4.2.  Interface Description Block (mandatory before EPB/ISB)
// Each interface is implicitly assigned an incremental unsigned 32-bit id
static void read_interface_description_block(uint32_t body_len) {
	pcapng_intf_descr_block_t intf_block;

	assert(body_len >= sizeof(intf_block));
	body_len -= _read(&intf_block, sizeof(intf_block));

	printf("  IDB - Linktype: %s (%u), Snaplen: %u\n",
					linktype_str(intf_block.linktype), intf_block.linktype, intf_block.snaplen);

	assert(intf_block.snaplen > 0);

	// TODO support multiple interfaces
	if(pkt_buf) {
		fprintf(stderr, "only one interface is supported\n");
		exit(1);
	}

	snaplen = intf_block.snaplen;
	pkt_buf = (u_char*) malloc(snaplen);
	if(!pkt_buf) {
		fprintf(stderr, "malloc pkt_buf failed[%d]: %s\n", errno, strerror(errno));
		exit(1);
	}

	// skip options
	_skip(body_len);
}

/* ******************************************************* */

// 4.3.  Enhanced Packet Block
static void read_enhanced_packet_block(uint32_t body_len, uint8_t verbose) {
	pcapng_enh_packet_block_t pkt_block;

	assert(body_len >= sizeof(pkt_block));
	body_len -= _read(&pkt_block, sizeof(pkt_block));

	// TODO read if_tsresol, support nanosecond resolution
	uint64_t tstamp_us = ((uint64_t)pkt_block.timestamp_high << 32) | pkt_block.timestamp_low;

	if(verbose)
		printf("  EPB [%u.%u] - Ifid: %d, Caplen: %u, Len: %u\n",
						(uint)(tstamp_us / 1000000), (uint)(tstamp_us % 1000000),
						pkt_block.interface_id, pkt_block.captured_len,
						pkt_block.packet_len);
	assert(pkt_block.captured_len <= body_len);
	assert(pkt_buf != NULL);

	if(verbose && (pkt_block.captured_len <= snaplen)) {
		body_len -= _read(pkt_buf, pkt_block.captured_len);
		hexdump(&pkt_buf, pkt_block.captured_len);
		puts("");
	}

	// skip pkt/padding/options
	_skip(body_len);
}

/* ******************************************************* */

// 4.7.  Decryption Secrets Block
static void read_decryption_secrets_block(uint32_t body_len, uint8_t verbose) {
	pcapng_decr_secrets_block_t sec_block;

	assert(body_len >= sizeof(sec_block));
	body_len -= _read(&sec_block, sizeof(sec_block));

	printf("  DSB - Type: %s (0x%08x), Len: %u\n",
						dsb_type_str(sec_block.secrets_type), sec_block.secrets_type,
						sec_block.secrets_length);

	assert(body_len >= sec_block.secrets_length);

	if(verbose && (sec_block.secrets_type == DSB_TYPE_TLS_KEYLOG)) {
		// https://firefox-source-docs.mozilla.org/security/nss/legacy/key_log_format/index.html
		char *keylog = (char*) malloc(sec_block.secrets_length + 1);
		if(keylog) {
			body_len -= _read(keylog, sec_block.secrets_length);
			keylog[sec_block.secrets_length] = '\0';

			printf("%s\n", keylog);
			free(keylog);
		}
	}

	// skip data/options
	_skip(body_len);
}

/* ******************************************************* */

static void usage() {
	fprintf(stderr, "usage: pcapng_parser inputfile [-v]\n");
	exit(1);
}

int main(int argc, char *argv[]) {
	if((argc != 2) && (argc != 3))
		usage();

	if((argc == 3) && strcmp(argv[2], "-v"))
		usage();

	uint8_t verbose = (argc == 3);
	uint8_t first_block = 1;

	inputf = fopen(argv[1], "rb");
	if(!inputf) {
		fprintf(stderr, "fopen %s failed[%d]: %s\n", argv[1], errno, strerror(errno));
		exit(1);
	}

	while(1) {
		pcapng_block_hdr_t block_hdr;
		_read(&block_hdr, sizeof(block_hdr));
		
		printf("[+%08lx] %s (0x%08x), Len: %u\n", ftell(inputf) - sizeof(block_hdr),
							block_type_str(block_hdr.type), block_hdr.type,
							block_hdr.total_length);
		if(first_block) {
			assert(block_hdr.type == BLOCK_TYPE_SHB);
			first_block = 0;
		}

		uint32_t block_tot_len = block_hdr.total_length;
		assert(block_tot_len >= MIN_BLOCK_SIZE);
		assert(block_tot_len < MAX_BLOCK_SIZE);
		if(block_tot_len % 4)
			block_tot_len += 4 - (block_tot_len % 4);

		uint32_t body_len = block_tot_len - MIN_BLOCK_SIZE;

		switch(block_hdr.type) {
			case BLOCK_TYPE_SHB:
				read_section_header_block(body_len);
				break;
			case BLOCK_TYPE_IDB:
				read_interface_description_block(body_len);
				break;
			case BLOCK_TYPE_EPB:
				read_enhanced_packet_block(body_len, verbose);
				break;
			case BLOCK_TYPE_DSB:
				read_decryption_secrets_block(body_len, verbose);
				break;
			default:
				_skip(body_len);
		}

		_skip(4 /* total_length_2 */);
	}

	if(pkt_buf)
		free(pkt_buf);

	fclose(inputf);
}
