/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"
#include "mount_internal.h"

static enum ntfs_result
mount_record_size(uint8_t code, uint32_t cluster, uint32_t *size)
{
	unsigned exponent;
	uint64_t decoded;

	if (code == 0) {
		return NTFS_CORRUPT;
	}
	if (code < NTFS_SIZE_CODE_EXPONENT_FLAG) {
		decoded = (uint64_t)code * cluster;
	} else {
		exponent = (UINT8_MAX + 1u) - code;
		if (exponent >= sizeof(uint32_t) * NTFS_BITS_PER_BYTE) {
			return NTFS_UNSUPPORTED;
		}
		decoded = UINT64_C(1) << exponent;
	}
	if (decoded < NTFS_MST_STRIDE || (decoded & (decoded - 1)) != 0) {
		return NTFS_CORRUPT;
	}
	if (decoded > NTFS_MAX_RECORD_BYTES) {
		return NTFS_UNSUPPORTED;
	}
	*size = (uint32_t)decoded;
	return NTFS_OK;
}

enum ntfs_result
ntfs_boot(const struct ntfs_environment *environment, struct ntfs_info *info, uint64_t *mft,
    uint64_t *mirror)
{
	struct ntfs_disk_boot boot;
	uint64_t sectors;
	uint32_t spc;
	enum ntfs_result result;

	if (environment == NULL || info == NULL || environment->api_version != NTFS_API_VERSION ||
	    environment->read == NULL) {
		return NTFS_INVALID;
	}
	ntfs_zero(info, sizeof(*info));
	if (environment->size_bytes < sizeof(boot)) {
		return NTFS_NOT_NTFS;
	}
	result = environment->read(environment->context, 0, &boot, sizeof(boot));
	if (result != NTFS_OK) {
		return result;
	}
	if (!ntfs_equal(boot.oem, "NTFS    ", sizeof(boot.oem))) {
		return NTFS_NOT_NTFS;
	}
	if (ntfs_u16(boot.signature) != NTFS_BOOT_SIGNATURE ||
	    ntfs_u16(boot.reserved_sectors) != 0 || boot.fat_count != 0 ||
	    ntfs_u16(boot.root_entries) != 0 || ntfs_u16(boot.small_sectors) != 0 ||
	    ntfs_u16(boot.sectors_per_fat) != 0 || ntfs_u32(boot.large_sectors) != 0) {
		return NTFS_CORRUPT;
	}
	info->sector_size = ntfs_u16(boot.sector_size);
	spc = boot.sectors_per_cluster;
	if (info->sector_size < NTFS_SECTOR_MIN_BYTES ||
	    info->sector_size > NTFS_SECTOR_MAX_BYTES ||
	    (info->sector_size & (info->sector_size - 1)) != 0 || spc == 0) {
		return NTFS_CORRUPT;
	}
	if ((spc & (spc - 1)) != 0) {
		return NTFS_UNSUPPORTED;
	}
	info->cluster_size = info->sector_size * spc;
	if (info->cluster_size > NTFS_MAX_CLUSTER_BYTES) {
		return NTFS_UNSUPPORTED;
	}
	sectors = ntfs_u64(boot.sectors);
	if (sectors == 0 || sectors > (uint64_t)INT64_MAX / info->sector_size) {
		return NTFS_CORRUPT;
	}
	info->size_bytes = sectors * info->sector_size;
	if (info->size_bytes > environment->size_bytes) {
		return NTFS_CORRUPT;
	}
	info->cluster_count = sectors / spc;
	*mft = ntfs_u64(boot.mft_lcn);
	*mirror = ntfs_u64(boot.mirror_lcn);
	if (*mft == 0 || *mirror == 0 || *mft == *mirror || *mft >= info->cluster_count ||
	    *mirror >= info->cluster_count) {
		return NTFS_CORRUPT;
	}
	result = mount_record_size(boot.record_code, info->cluster_size, &info->record_size);
	if (result == NTFS_OK) {
		result = mount_record_size(boot.index_code, info->cluster_size, &info->index_size);
	}
	info->serial = ntfs_u64(boot.serial);
	return result;
}

enum ntfs_result
ntfs_probe(const struct ntfs_environment *environment, struct ntfs_info *info)
{
	uint64_t mft, mirror;

	return ntfs_boot(environment, info, &mft, &mirror);
}

static enum ntfs_result
mount_load_information(struct ntfs_volume *volume)
{
	struct ntfs_node *node = NULL;
	struct ntfs_attr_view attribute_view;
	const uint8_t *bytes = NULL;
	const struct ntfs_disk_volume_info *info;
	size_t size = 0, i, written;
	uint16_t label[NTFS_NAME_MAX];
	enum ntfs_result result;

	result = ntfs_node_by_number(volume, NTFS_VOLUME_RECORD, &node);
	if (result != NTFS_OK) {
		return result;
	}
	result = ntfs_attr_find(node->record, volume->info.record_size, NTFS_ATTR_VOLUME_INFO, NULL,
	    0, UINT16_MAX, &attribute_view);
	if (result == NTFS_OK) {
		result = ntfs_attr_value(&attribute_view, &bytes, &size);
	}
	if (result == NTFS_OK && size < sizeof(*info)) {
		result = NTFS_CORRUPT;
	}
	if (result == NTFS_OK) {
		info = (const void *)bytes;
		volume->info.major_version = info->major;
		volume->info.minor_version = info->minor;
		volume->info.volume_flags = ntfs_u16(info->flags);
		if (info->major != NTFS_VOLUME_MAJOR_VERSION ||
		    info->minor > NTFS_VOLUME_MAX_MINOR_VERSION) {
			result = NTFS_UNSUPPORTED;
		} else if ((volume->info.volume_flags & NTFS_VOLUME_DIRTY) != 0) {
			result = NTFS_DIRTY;
		} else if ((volume->info.volume_flags & ~NTFS_VOLUME_DISABLE_SHORT_NAMES) != 0 ||
		    (volume->info.volume_flags != 0 &&
			info->minor != NTFS_VOLUME_SHORT_NAMES_MINOR_VERSION)) {
			result = NTFS_UNSUPPORTED;
		}
	}
	if (result == NTFS_OK) {
		result = ntfs_attr_find(node->record, volume->info.record_size,
		    NTFS_ATTR_VOLUME_NAME, NULL, 0, UINT16_MAX, &attribute_view);
		if (result == NTFS_NOT_FOUND) {
			result = NTFS_OK;
		} else if (result == NTFS_OK) {
			result = ntfs_attr_value(&attribute_view, &bytes, &size);
			if (result == NTFS_OK &&
			    (size % NTFS_UTF16_UNIT_BYTES != 0 ||
				size / NTFS_UTF16_UNIT_BYTES > NTFS_NAME_MAX)) {
				result = NTFS_CORRUPT;
			}
			if (result == NTFS_OK) {
				for (i = 0; i < size / NTFS_UTF16_UNIT_BYTES; i++) {
					label[i] = ntfs_u16(bytes + i * NTFS_UTF16_UNIT_BYTES);
				}
				result = ntfs_utf16_to_utf8(label, size / NTFS_UTF16_UNIT_BYTES,
				    volume->info.label, NTFS_UTF8_NAME_MAX, &written);
				if (result == NTFS_OK) {
					volume->info.label[written] = 0;
				}
			}
		}
	}
	ntfs_node_close(node);
	return result;
}

static enum ntfs_result
mount_boot_read(void *context, uint64_t offset, void *bytes, size_t size)
{
	struct ntfs_volume *volume = context;
	enum ntfs_result result;

	result = ntfs_operation_read(volume, size);
	return result == NTFS_OK ? volume->env.read(volume->env.context, offset, bytes, size)
				 : result;
}

static enum ntfs_result
mount_source(const struct ntfs_environment *environment, const struct ntfs_limits *limits,
    struct ntfs_volume **out, bool namespace_admission)
{
	struct ntfs_volume *volume;
	struct ntfs_limits configured;
	struct ntfs_environment boot_environment;
	struct ntfs_node *node = NULL;
	struct ntfs_stream *upcase = NULL;
	struct ntfs_directory *directory = NULL;
	uint8_t *record = NULL, *mirror = NULL;
	size_t usa_sequence_end, usa_sequence_offset;
	uint32_t i;
	bool entered = false;
	enum ntfs_result result;

	if (out == NULL) {
		return NTFS_INVALID;
	}
	*out = NULL;
	if (environment == NULL || environment->api_version != NTFS_API_VERSION ||
	    environment->read == NULL || environment->allocate == NULL ||
	    environment->release == NULL) {
		return NTFS_INVALID;
	}
	ntfs_default_limits(&configured);
	if (limits != NULL) {
		configured = *limits;
	}
	if (configured.max_runs == 0 || configured.max_runs > NTFS_MAX_CONFIGURED_RUNS ||
	    configured.max_attribute_list == 0 ||
	    configured.max_attribute_list > NTFS_MAX_CONFIGURED_ATTRIBUTE_LIST ||
	    configured.record_cache_entries > NTFS_MAX_CONFIGURED_RECORD_CACHE ||
	    configured.max_directory_nodes == 0 ||
	    configured.max_directory_nodes > NTFS_MAX_CONFIGURED_DIRECTORY_NODES ||
	    configured.max_live_bytes == 0 || !ntfs_operation_limits_valid(&configured.operation)) {
		return NTFS_INVALID;
	}
	if (sizeof(*volume) > configured.max_live_bytes ||
	    sizeof(*volume) > configured.operation.allocation_bytes) {
		return NTFS_NO_MEMORY;
	}
	volume = environment->allocate(environment->context, sizeof(*volume));
	if (volume == NULL) {
		return NTFS_NO_MEMORY;
	}
	ntfs_zero(volume, sizeof(*volume));
	volume->env = *environment;
	volume->limits = configured;
	volume->live_bytes = sizeof(*volume);
	result = ntfs_operation_enter(volume);
	if (result != NTFS_OK) {
		goto finish;
	}
	entered = true;
	/* The sole bootstrap allocation preceded storage for its accounting. */
	volume->operation->usage.allocation_calls = 1;
	volume->operation->usage.allocation_bytes = sizeof(*volume);
	boot_environment = *environment;
	boot_environment.context = volume;
	boot_environment.read = mount_boot_read;
	result = ntfs_work(volume, sizeof(struct ntfs_disk_boot));
	if (result == NTFS_OK) {
		result = ntfs_boot(
		    &boot_environment, &volume->info, &volume->mft_lcn, &volume->mirror_lcn);
	}
	if (result != NTFS_OK) {
		goto finish;
	}
	record = ntfs_alloc(volume, volume->info.record_size);
	mirror = ntfs_alloc(volume, volume->info.record_size);
	if (record == NULL || mirror == NULL) {
		result = NTFS_NO_MEMORY;
		goto finish;
	}
	result = ntfs_io(
	    volume, volume->mft_lcn * volume->info.cluster_size, record, volume->info.record_size);
	if (result == NTFS_OK) {
		result = ntfs_work(volume, volume->info.record_size);
	}
	if (result == NTFS_OK) {
		result = ntfs_record_validate(record, volume->info.record_size);
	}
	if (result == NTFS_OK) {
		result = ntfs_io(volume, volume->mirror_lcn * volume->info.cluster_size, mirror,
		    volume->info.record_size);
	}
	if (result == NTFS_OK) {
		result = ntfs_work(volume, volume->info.record_size);
	}
	if (result == NTFS_OK) {
		result = ntfs_record_validate(mirror, volume->info.record_size);
	}
	if (result == NTFS_OK) {
		/* Both complete FILEs passed MST restoration. A replica has its own
		 * physical protection counter; compare every other restored byte,
		 * including USA geometry and saved tails, without requiring that counter. */
		usa_sequence_offset = ntfs_u16(
		    ((const struct ntfs_disk_record *)(const void *)record)->mst.usa_offset);
		usa_sequence_end = usa_sequence_offset + NTFS_MST_WORD_BYTES;
		if (!ntfs_equal(record, mirror, usa_sequence_offset) ||
		    !ntfs_equal(record + usa_sequence_end, mirror + usa_sequence_end,
			volume->info.record_size - usa_sequence_end)) {
			result = NTFS_CORRUPT;
		}
	}
	if (result != NTFS_OK) {
		goto finish;
	}
	result = ntfs_mft_open(volume, record, &volume->mft);
	if (result != NTFS_OK) {
		goto finish;
	}
	if (volume->mft->resident || volume->mft->flags != 0 ||
	    volume->mft->initialized != volume->mft->size ||
	    volume->mft->size % volume->info.record_size != 0 || volume->mft->run_count == 0 ||
	    volume->mft->runs[0].lcn != volume->mft_lcn ||
	    volume->mft->clusters > INT64_MAX / volume->info.cluster_size ||
	    volume->mft->clusters * volume->info.cluster_size < volume->mft->size) {
		result = NTFS_CORRUPT;
		goto finish;
	}
	if (volume->limits.record_cache_entries != 0) {
		volume->cache = ntfs_alloc(
		    volume, (size_t)volume->limits.record_cache_entries * sizeof(*volume->cache));
		if (volume->cache == NULL) {
			result = NTFS_NO_MEMORY;
			goto finish;
		}
	}
	result = mount_load_information(volume);
	if (result == NTFS_OK) {
		result = ntfs_node_by_number(volume, NTFS_UPCASE_RECORD, &node);
	}
	if (result == NTFS_OK) {
		result = ntfs_attribute_open(node, NTFS_ATTRIBUTE_DATA, NULL, 0, &upcase);
	}
	if (result != NTFS_OK) {
		goto finish;
	}
	if (upcase->size != NTFS_UPCASE_BYTES || upcase->initialized != upcase->size ||
	    upcase->flags != 0) {
		result = NTFS_CORRUPT;
		goto finish;
	}
	volume->upcase = ntfs_alloc(volume, NTFS_UPCASE_BYTES);
	if (volume->upcase == NULL) {
		result = NTFS_NO_MEMORY;
		goto finish;
	}
	result = ntfs_stream_exact(upcase, 0, volume->upcase, NTFS_UPCASE_BYTES);
	if (result != NTFS_OK) {
		goto finish;
	}
	result = ntfs_work(volume, NTFS_UTF16_CODE_UNITS);
	if (result != NTFS_OK) {
		goto finish;
	}
	for (i = 0; i < NTFS_UTF16_CODE_UNITS; i++) {
		if (ntfs_u16(volume->upcase +
			(size_t)ntfs_u16(volume->upcase + i * NTFS_UTF16_UNIT_BYTES) *
			    NTFS_UTF16_UNIT_BYTES) !=
		    ntfs_u16(volume->upcase + i * NTFS_UTF16_UNIT_BYTES)) {
			result = NTFS_CORRUPT;
			goto finish;
		}
	}
	for (i = 'a'; i <= 'z'; i++) {
		if (ntfs_u16(volume->upcase + i * NTFS_UTF16_UNIT_BYTES) != i - 'a' + 'A') {
			result = NTFS_CORRUPT;
			goto finish;
		}
	}
	ntfs_node_close(node);
	node = NULL;
	if (namespace_admission) {
		result = ntfs_root(volume, &node);
		if (result == NTFS_OK) {
			result = ntfs_directory_open(node, &directory);
		}
	}
finish:
	ntfs_directory_close(directory);
	ntfs_node_close(node);
	ntfs_stream_close(upcase);
	ntfs_free(volume, record, volume->info.record_size);
	ntfs_free(volume, mirror, volume->info.record_size);
	if (entered) {
		ntfs_operation_leave(volume);
	}
	if (result != NTFS_OK) {
		(void)ntfs_unmount(volume);
		return result;
	}
	*out = volume;
	return NTFS_OK;
}

enum ntfs_result
ntfs_mount(const struct ntfs_environment *environment, const struct ntfs_limits *limits,
    struct ntfs_volume **out)
{
	return mount_source(environment, limits, out, true);
}

enum ntfs_result
ntfs_mount_journal(const struct ntfs_environment *environment, const struct ntfs_limits *limits,
    struct ntfs_volume **out)
{
	return mount_source(environment, limits, out, false);
}

enum ntfs_result
ntfs_unmount(struct ntfs_volume *volume)
{
	uint32_t i;
	struct ntfs_environment environment;

	if (volume == NULL) {
		return NTFS_OK;
	}
	if (volume->children != 0 || volume->operation_calls != 0) {
		return NTFS_BUSY;
	}
	ntfs_operation_detach(volume);
	environment = volume->env;
	ntfs_stream_close(volume->mft);
	ntfs_free(volume, volume->upcase, NTFS_UPCASE_BYTES);
	if (volume->cache != NULL) {
		for (i = 0; i < volume->limits.record_cache_entries; i++) {
			ntfs_free(volume, volume->cache[i].bytes, volume->info.record_size);
		}
		ntfs_free(volume, volume->cache,
		    (size_t)volume->limits.record_cache_entries * sizeof(*volume->cache));
	}
	environment.release(environment.context, volume, sizeof(*volume));
	return NTFS_OK;
}

void
ntfs_get_info(const struct ntfs_volume *volume, struct ntfs_info *out)
{
	*out = volume->info;
}

void
ntfs_get_io_statistics(const struct ntfs_volume *volume, struct ntfs_io_statistics *out)
{
	*out = volume->stats;
}

enum ntfs_result
ntfs_count_free_clusters_impl(struct ntfs_volume *volume, uint64_t *free_clusters)
{
	struct ntfs_node *node = NULL;
	struct ntfs_stream *bitmap = NULL;
	uint8_t *buffer = NULL;
	uint64_t bytes, offset = 0, count = 0, cluster;
	size_t take, i;
	unsigned bit;
	enum ntfs_result result;

	if (volume == NULL || free_clusters == NULL) {
		return NTFS_INVALID;
	}
	*free_clusters = 0;
	bytes = (volume->info.cluster_count + NTFS_BITS_PER_BYTE - 1) / NTFS_BITS_PER_BYTE;
	result = ntfs_node_by_number(volume, NTFS_BITMAP_RECORD, &node);
	if (result == NTFS_OK) {
		result = ntfs_attribute_open(node, NTFS_ATTRIBUTE_DATA, NULL, 0, &bitmap);
	}
	if (result != NTFS_OK) {
		goto finish;
	}
	if (bitmap->size < bytes || bitmap->initialized < bytes || bitmap->flags != 0) {
		result = NTFS_CORRUPT;
		goto finish;
	}
	buffer = ntfs_alloc(volume, NTFS_BITMAP_SCAN_BYTES);
	if (buffer == NULL) {
		result = NTFS_NO_MEMORY;
		goto finish;
	}
	while (offset < bytes) {
		take = bytes - offset < NTFS_BITMAP_SCAN_BYTES ? (size_t)(bytes - offset)
							       : NTFS_BITMAP_SCAN_BYTES;
		result = ntfs_stream_exact(bitmap, offset, buffer, take);
		if (result != NTFS_OK) {
			goto finish;
		}
		/* One byte has a fixed NTFS_BITS_PER_BYTE bit-count loop. */
		result = ntfs_work(volume, take);
		if (result != NTFS_OK) {
			goto finish;
		}
		for (i = 0; i < take; i++) {
			for (bit = 0; bit < NTFS_BITS_PER_BYTE; bit++) {
				cluster = (offset + i) * NTFS_BITS_PER_BYTE + bit;
				if (cluster < volume->info.cluster_count &&
				    (buffer[i] & (1u << bit)) == 0) {
					count++;
				}
			}
		}
		offset += take;
	}
	*free_clusters = count;
finish:
	ntfs_free(volume, buffer, NTFS_BITMAP_SCAN_BYTES);
	ntfs_stream_close(bitmap);
	ntfs_node_close(node);
	return result;
}
