/*
 *  mod_odex by Collin Mulliner <collinATmulliner.org>
 *  - patch the DEX crc in ODEX files
 *  license: GPLv3
 *  http://www.mulliner.org/android/
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#define DEBUG 1

struct oat_header_t
{
	char magic[4];
	char version[4];
	uint32_t adler32_checksum;
	uint32_t instruction_set;
	uint32_t instruction_set_features;
	uint32_t dex_file_count;
	uint32_t data[11]; // this seams to change deppening on the oat version (11 = 064)
	uint32_t key_value_store_size;
	// unsigned char key_value_store;
};

// not used, just to remember the structure
/*
struct oat_dex_file_header_t
{
	uint32_t dex_file_location_size;
	char dex_file_location[1];
	uint32_t dex_file_location_checksum;
	uint32_t dex_file_pointer;
	// classes_offsets
};
*/

void parse_oat_dex_file_header(unsigned char *data, int count, uint32_t oldcrc, uint32_t newcrc)
{
	// this is the name of the apk once it gets installed on the device
	char baseapk[] = {"base.apk"};
	unsigned char *dp = data;
	int c = count;
	char name_tmp[128];

	while (c > 0) {
		if (memcmp(dp, baseapk, 8) == 0) {
			uint32_t *namelen = (uint32_t*) (dp - 4);
			printf("classes len: %d\n", *namelen);
			memcpy(name_tmp, dp, *namelen);
			name_tmp[*namelen] = 0;
			printf("classes: %s\n", name_tmp);
			uint32_t *crc32 = (uint32_t*)(dp + *namelen);
			printf("classes crc32: %.8X\n", *crc32);

			if (oldcrc != 0 && newcrc != 0) {
				if (*crc32 == oldcrc) {
					*crc32 = newcrc;
					printf("!classes crc32: %.8X\n", *crc32);
				}
			}

			c--;
			dp += *namelen + 8;
		}
		dp++;
	}
}

void parse_odex(unsigned char *odex, uint32_t oldcrc, uint32_t newcrc)
{
	struct oat_header_t *oat = (struct oat_header_t*) odex;
	printf("%c%c%c%c\n", oat->magic[0],oat->magic[1],oat->magic[2],oat->magic[3]);
	printf("dex file count: %d\n", oat->dex_file_count);
	printf("key_value_store_size: %d\n", oat->key_value_store_size);
	
	// find key value store
	char *kvs = odex + sizeof(struct oat_header_t);
	printf("kvs[0]: %s\n", kvs);
	
	parse_oat_dex_file_header(kvs + oat->key_value_store_size, oat->dex_file_count, oldcrc, newcrc);
}

int main(int argc, char **argv)
{
	if (argc == 1) {
		printf("%s: file_name.odex [oldcrc:newcrc]\n\tif CRCs are provided the oldcrc will be replaced with the newcrc\n", argv[0]);
		exit(0);
	}

	struct stat fs;
	int fp = open(argv[1], O_RDWR);
	fstat(fp, &fs);
	void *dex = mmap(0, fs.st_size, PROT_READ|PROT_WRITE, MAP_SHARED, fp, 0);

	uint32_t oldcrc = 0;
	uint32_t newcrc = 0;

	if (argc == 3) {
		if (strlen(argv[2]) == 17) {
			argv[2][8] = 0;
			oldcrc = strtol(&argv[2][0], 0, 16);
			newcrc = strtol(&argv[2][9], 0, 16);
			printf("old crc: %.8X  new crc: %.8X\n", oldcrc, newcrc);
		}
	}

	// search (e.g. oat/odex files)
	char dexid[] = {'o','a','t', '\n'};
	unsigned char *d = (unsigned char*)dex;
	for (uint32_t i = 0; i < fs.st_size; i++) {
		if (memcmp(d, dexid, 4) == 0) {
			printf("%s\n", d);
			printf("offset = %d\n", i);
			break;
		}
		d++;
	}

	parse_odex((unsigned char*)d, oldcrc, newcrc);

	munmap(dex, fs.st_size);
	close(fp);
}
