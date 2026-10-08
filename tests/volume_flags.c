/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include <ntfs/ntfs.h>
#include "fuzz_device.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
	TEST_PATH_BYTES = 1024,
	TEST_NAME_BYTES = 128,
	TEST_IMAGE_BYTES = 1024 * 1024,
	TEST_VOLUME_MAJOR = 3,
	TEST_VOLUME_MINOR = 1,
	TEST_FIELDS = 5,
	TEST_CASES = 78,
	TEST_REPETITIONS = 2
};

static uint8_t *
read_image(const char *directory, const char *name)
{
	char path[TEST_PATH_BYTES];
	uint8_t *bytes;
	FILE *file;
	int length;

	length = snprintf(path, sizeof(path), "%s/%s", directory, name);
	assert(length > 0 && (size_t)length < sizeof(path));
	file = fopen(path, "rb");
	assert(file != NULL);
	bytes = malloc(TEST_IMAGE_BYTES);
	assert(bytes != NULL && fread(bytes, 1, TEST_IMAGE_BYTES, file) == TEST_IMAGE_BYTES);
	assert(fgetc(file) == EOF && !ferror(file) && fclose(file) == 0);
	return bytes;
}

static void
accepted(struct ntfs_volume *volume, unsigned major, unsigned minor, unsigned flags)
{
	struct ntfs_info info;
	struct ntfs_node *root = NULL;

	assert(volume != NULL);
	ntfs_get_info(volume, &info);
	assert(info.major_version == major && info.minor_version == minor &&
	    info.volume_flags == flags);
	assert(ntfs_root(volume, &root) == NTFS_OK && root != NULL);
	ntfs_node_close(root);
	assert(ntfs_unmount(volume) == NTFS_OK);
}

int
main(int argc, char **argv)
{
	struct fuzz_device device;
	struct ntfs_environment env;
	struct ntfs_volume *volume;
	char path[TEST_PATH_BYTES], name[TEST_NAME_BYTES], scan[TEST_NAME_BYTES];
	FILE *cases;
	uint8_t *bytes, *backup, *clean, *clean_backup;
	size_t count = 0, repetition;
	unsigned major, minor, flags, code;
	enum ntfs_result result;

	assert(argc == 2);
	assert(snprintf(path, sizeof(path), "%s/cases.tsv", argv[1]) > 0);
	assert(snprintf(scan, sizeof(scan), "%%%zus %%u %%u %%u %%u", sizeof(name) - 1) > 0);
	cases = fopen(path, "r");
	assert(cases != NULL);
	clean = read_image(argv[1], "clean-version-1.img");
	backup = malloc(TEST_IMAGE_BYTES);
	clean_backup = malloc(TEST_IMAGE_BYTES);
	assert(backup != NULL && clean_backup != NULL);
	memcpy(clean_backup, clean, TEST_IMAGE_BYTES);
	while (fscanf(cases, scan, name, &major, &minor, &flags, &code) == TEST_FIELDS) {
		assert(code == NTFS_OK || code == NTFS_DIRTY || code == NTFS_UNSUPPORTED);
		bytes = read_image(argv[1], name);
		memcpy(backup, bytes, TEST_IMAGE_BYTES);
		device = (struct fuzz_device){.data = bytes, .size = TEST_IMAGE_BYTES};
		env = fuzz_environment(&device);
		for (repetition = 0; repetition < TEST_REPETITIONS; repetition++) {
			device.reads = 0;
			volume = (struct ntfs_volume *)(uintptr_t)UINTPTR_MAX;
			result = ntfs_mount(&env, NULL, &volume);
			if (result != (enum ntfs_result)code) {
				fprintf(stderr, "%s: result=%u expected=%u\n", name,
				    (unsigned)result, code);
			}
			assert(result == (enum ntfs_result)code);
			if (result == NTFS_OK) {
				accepted(volume, major, minor, flags);
			} else {
				assert(volume == NULL);
			}
			assert(device.memory == 0 && memcmp(bytes, backup, TEST_IMAGE_BYTES) == 0);
		}
		/* A refusal must leave no owner behind or poison reuse of the callbacks. */
		device.data = clean;
		device.reads = 0;
		assert(ntfs_mount(&env, NULL, &volume) == NTFS_OK);
		accepted(volume, TEST_VOLUME_MAJOR, TEST_VOLUME_MINOR, 0);
		assert(device.memory == 0 && memcmp(clean, clean_backup, TEST_IMAGE_BYTES) == 0);
		free(bytes);
		count++;
	}
	assert(feof(cases) && fclose(cases) == 0 && count == TEST_CASES);
	free(backup);
	free(clean_backup);
	free(clean);
	printf("PASS: %zu volume admission profiles, repeated exact results, "
	       "unchanged inputs, owner cleanup and clean callback reuse\n",
	    count);
	return 0;
}
