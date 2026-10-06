/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#include "internal.h"

static enum ntfs_result
record_size(uint8_t code, uint32_t cluster, uint32_t *size)
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
ntfs_boot(
    const struct ntfs_environment *env, struct ntfs_info *info, uint64_t *mft, uint64_t *mirror)
{
	struct ntfs_disk_boot boot;
	uint64_t sectors;
	uint32_t spc;
	enum ntfs_result result;

	if (env == NULL || info == NULL || env->api_version != NTFS_API_VERSION ||
	    env->read == NULL) {
		return NTFS_INVALID;
	}
	ntfs_zero(info, sizeof(*info));
	if (env->size_bytes < sizeof(boot)) {
		return NTFS_NOT_NTFS;
	}
	result = env->read(env->context, 0, &boot, sizeof(boot));
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
	if (info->size_bytes > env->size_bytes) {
		return NTFS_CORRUPT;
	}
	info->cluster_count = sectors / spc;
	*mft = ntfs_u64(boot.mft_lcn);
	*mirror = ntfs_u64(boot.mirror_lcn);
	if (*mft == 0 || *mirror == 0 || *mft == *mirror || *mft >= info->cluster_count ||
	    *mirror >= info->cluster_count) {
		return NTFS_CORRUPT;
	}
	result = record_size(boot.record_code, info->cluster_size, &info->record_size);
	if (result == NTFS_OK) {
		result = record_size(boot.index_code, info->cluster_size, &info->index_size);
	}
	info->serial = ntfs_u64(boot.serial);
	return result;
}

enum ntfs_result
ntfs_probe(const struct ntfs_environment *env, struct ntfs_info *info)
{
	uint64_t mft, mirror;

	return ntfs_boot(env, info, &mft, &mirror);
}

static enum ntfs_result
load_information(struct ntfs_volume *v)
{
	struct ntfs_node *node = NULL;
	struct ntfs_attr_view attr;
	const uint8_t *bytes = NULL;
	const struct ntfs_disk_volume_info *info;
	size_t size = 0, i, written;
	uint16_t label[NTFS_NAME_MAX];
	enum ntfs_result result;

	result = ntfs_node_by_number(v, NTFS_VOLUME_RECORD, &node);
	if (result != NTFS_OK) {
		return result;
	}
	result = ntfs_attr_find(
	    node->record, v->info.record_size, NTFS_ATTR_VOLUME_INFO, NULL, 0, UINT16_MAX, &attr);
	if (result == NTFS_OK) {
		result = ntfs_attr_value(&attr, &bytes, &size);
	}
	if (result == NTFS_OK && size < sizeof(*info)) {
		result = NTFS_CORRUPT;
	}
	if (result == NTFS_OK) {
		info = (const void *)bytes;
		v->info.major_version = info->major;
		v->info.minor_version = info->minor;
		v->info.volume_flags = ntfs_u16(info->flags);
		if (info->major != NTFS_VOLUME_MAJOR_VERSION ||
		    info->minor > NTFS_VOLUME_MAX_MINOR_VERSION) {
			result = NTFS_UNSUPPORTED;
		} else if ((v->info.volume_flags & NTFS_VOLUME_DIRTY) != 0) {
			result = NTFS_DIRTY;
		} else if (v->info.volume_flags != 0) {
			result = NTFS_UNSUPPORTED;
		}
	}
	if (result == NTFS_OK) {
		result = ntfs_attr_find(node->record, v->info.record_size, NTFS_ATTR_VOLUME_NAME,
		    NULL, 0, UINT16_MAX, &attr);
		if (result == NTFS_NOT_FOUND) {
			result = NTFS_OK;
		} else if (result == NTFS_OK) {
			result = ntfs_attr_value(&attr, &bytes, &size);
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
				    v->info.label, NTFS_UTF8_NAME_MAX, &written);
				if (result == NTFS_OK) {
					v->info.label[written] = 0;
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

enum ntfs_result
ntfs_mount(
    const struct ntfs_environment *env, const struct ntfs_limits *limits, struct ntfs_volume **out)
{
	struct ntfs_volume *v;
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
	if (env == NULL || env->api_version != NTFS_API_VERSION || env->read == NULL ||
	    env->allocate == NULL || env->release == NULL) {
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
	if (sizeof(*v) > configured.max_live_bytes ||
	    sizeof(*v) > configured.operation.allocation_bytes) {
		return NTFS_NO_MEMORY;
	}
	v = env->allocate(env->context, sizeof(*v));
	if (v == NULL) {
		return NTFS_NO_MEMORY;
	}
	ntfs_zero(v, sizeof(*v));
	v->env = *env;
	v->limits = configured;
	v->live_bytes = sizeof(*v);
	result = ntfs_operation_enter(v);
	if (result != NTFS_OK) {
		goto finish;
	}
	entered = true;
	/* The sole bootstrap allocation preceded storage for its accounting. */
	v->operation->usage.allocation_calls = 1;
	v->operation->usage.allocation_bytes = sizeof(*v);
	boot_environment = *env;
	boot_environment.context = v;
	boot_environment.read = mount_boot_read;
	result = ntfs_work(v, sizeof(struct ntfs_disk_boot));
	if (result == NTFS_OK) {
		result = ntfs_boot(&boot_environment, &v->info, &v->mft_lcn, &v->mirror_lcn);
	}
	if (result != NTFS_OK) {
		goto finish;
	}
	record = ntfs_alloc(v, v->info.record_size);
	mirror = ntfs_alloc(v, v->info.record_size);
	if (record == NULL || mirror == NULL) {
		result = NTFS_NO_MEMORY;
		goto finish;
	}
	result = ntfs_io(v, v->mft_lcn * v->info.cluster_size, record, v->info.record_size);
	if (result == NTFS_OK) {
		result = ntfs_work(v, v->info.record_size);
	}
	if (result == NTFS_OK) {
		result = ntfs_record_validate(record, v->info.record_size);
	}
	if (result == NTFS_OK) {
		result =
		    ntfs_io(v, v->mirror_lcn * v->info.cluster_size, mirror, v->info.record_size);
	}
	if (result == NTFS_OK) {
		result = ntfs_work(v, v->info.record_size);
	}
	if (result == NTFS_OK) {
		result = ntfs_record_validate(mirror, v->info.record_size);
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
			v->info.record_size - usa_sequence_end)) {
			result = NTFS_CORRUPT;
		}
	}
	if (result != NTFS_OK) {
		goto finish;
	}
	result = ntfs_mft_open(v, record, &v->mft);
	if (result != NTFS_OK) {
		goto finish;
	}
	if (v->mft->resident || v->mft->flags != 0 || v->mft->initialized != v->mft->size ||
	    v->mft->size % v->info.record_size != 0 || v->mft->run_count == 0 ||
	    v->mft->runs[0].lcn != v->mft_lcn ||
	    v->mft->clusters > INT64_MAX / v->info.cluster_size ||
	    v->mft->clusters * v->info.cluster_size < v->mft->size) {
		result = NTFS_CORRUPT;
		goto finish;
	}
	if (v->limits.record_cache_entries != 0) {
		v->cache =
		    ntfs_alloc(v, (size_t)v->limits.record_cache_entries * sizeof(*v->cache));
		if (v->cache == NULL) {
			result = NTFS_NO_MEMORY;
			goto finish;
		}
	}
	result = load_information(v);
	if (result == NTFS_OK) {
		result = ntfs_node_by_number(v, NTFS_UPCASE_RECORD, &node);
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
	v->upcase = ntfs_alloc(v, NTFS_UPCASE_BYTES);
	if (v->upcase == NULL) {
		result = NTFS_NO_MEMORY;
		goto finish;
	}
	result = ntfs_stream_exact(upcase, 0, v->upcase, NTFS_UPCASE_BYTES);
	if (result != NTFS_OK) {
		goto finish;
	}
	result = ntfs_work(v, NTFS_UTF16_CODE_UNITS);
	if (result != NTFS_OK) {
		goto finish;
	}
	for (i = 0; i < NTFS_UTF16_CODE_UNITS; i++) {
		if (ntfs_u16(v->upcase +
			(size_t)ntfs_u16(v->upcase + i * NTFS_UTF16_UNIT_BYTES) *
			    NTFS_UTF16_UNIT_BYTES) !=
		    ntfs_u16(v->upcase + i * NTFS_UTF16_UNIT_BYTES)) {
			result = NTFS_CORRUPT;
			goto finish;
		}
	}
	for (i = 'a'; i <= 'z'; i++) {
		if (ntfs_u16(v->upcase + i * NTFS_UTF16_UNIT_BYTES) != i - 'a' + 'A') {
			result = NTFS_CORRUPT;
			goto finish;
		}
	}
	ntfs_node_close(node);
	node = NULL;
	result = ntfs_root(v, &node);
	if (result == NTFS_OK) {
		result = ntfs_directory_open(node, &directory);
	}
finish:
	ntfs_directory_close(directory);
	ntfs_node_close(node);
	ntfs_stream_close(upcase);
	ntfs_free(v, record, v->info.record_size);
	ntfs_free(v, mirror, v->info.record_size);
	if (entered) {
		ntfs_operation_leave(v);
	}
	if (result != NTFS_OK) {
		(void)ntfs_unmount(v);
		return result;
	}
	*out = v;
	return NTFS_OK;
}

enum ntfs_result
ntfs_unmount(struct ntfs_volume *v)
{
	uint32_t i;
	struct ntfs_environment env;

	if (v == NULL) {
		return NTFS_OK;
	}
	if (v->children != 0 || v->operation_calls != 0) {
		return NTFS_BUSY;
	}
	ntfs_operation_detach(v);
	env = v->env;
	ntfs_stream_close(v->mft);
	ntfs_free(v, v->upcase, NTFS_UPCASE_BYTES);
	if (v->cache != NULL) {
		for (i = 0; i < v->limits.record_cache_entries; i++) {
			ntfs_free(v, v->cache[i].bytes, v->info.record_size);
		}
		ntfs_free(v, v->cache, (size_t)v->limits.record_cache_entries * sizeof(*v->cache));
	}
	env.release(env.context, v, sizeof(*v));
	return NTFS_OK;
}

void
ntfs_get_info(const struct ntfs_volume *v, struct ntfs_info *out)
{
	*out = v->info;
}

void
ntfs_get_io_statistics(const struct ntfs_volume *v, struct ntfs_io_statistics *out)
{
	*out = v->stats;
}

enum ntfs_result
ntfs_count_free_clusters_impl(struct ntfs_volume *v, uint64_t *free_clusters)
{
	struct ntfs_node *node = NULL;
	struct ntfs_stream *bitmap = NULL;
	uint8_t *buffer = NULL;
	uint64_t bytes, offset = 0, count = 0, cluster;
	size_t take, i;
	unsigned bit;
	enum ntfs_result result;

	if (v == NULL || free_clusters == NULL) {
		return NTFS_INVALID;
	}
	*free_clusters = 0;
	bytes = (v->info.cluster_count + NTFS_BITS_PER_BYTE - 1) / NTFS_BITS_PER_BYTE;
	result = ntfs_node_by_number(v, NTFS_BITMAP_RECORD, &node);
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
	buffer = ntfs_alloc(v, NTFS_BITMAP_SCAN_BYTES);
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
		result = ntfs_work(v, take);
		if (result != NTFS_OK) {
			goto finish;
		}
		for (i = 0; i < take; i++) {
			for (bit = 0; bit < NTFS_BITS_PER_BYTE; bit++) {
				cluster = (offset + i) * NTFS_BITS_PER_BYTE + bit;
				if (cluster < v->info.cluster_count &&
				    (buffer[i] & (1u << bit)) == 0) {
					count++;
				}
			}
		}
		offset += take;
	}
	*free_clusters = count;
finish:
	ntfs_free(v, buffer, NTFS_BITMAP_SCAN_BYTES);
	ntfs_stream_close(bitmap);
	ntfs_node_close(node);
	return result;
}
