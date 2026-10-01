/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#import "NTFSResource.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>

static enum ntfs_result
resource_read(void *context, uint64_t offset, void *buffer, size_t length)
{
	return [(__bridge NTFSResource *)context readAt:offset bytes:buffer length:length];
}

static void *
resource_allocate(void *context, size_t size)
{
	return [(__bridge NTFSResource *)context allocateSize:size];
}

static void
resource_release(void *context, void *buffer, size_t size)
{
	[(__bridge NTFSResource *)context releaseBytes:buffer size:size];
}

@implementation NTFSResource {
	id<NTFSBlockReader> _reader;
	uint64_t _size;
	size_t _alignment;
	void *_window;
	size_t _allocatedBytes;
}

- (instancetype)initWithReader:(id<NTFSBlockReader>)reader
{
	uint64_t block = reader.blockSize, count = reader.blockCount;
	uint64_t alignment = MAX(reader.physicalBlockSize, block);

	if (block == 0 || count == 0 || count > INT64_MAX / block ||
	    alignment < NTFS_RESOURCE_MIN_ALIGNMENT || alignment > NTFS_RESOURCE_MAX_ALIGNMENT ||
	    (alignment & (alignment - 1)) != 0 || count * block % alignment != 0) {
		return nil;
	}
	self = [super init];
	if (self != nil) {
		_reader = reader;
		_size = block * count;
		_alignment = (size_t)alignment;
		if (posix_memalign(&_window, _alignment, NTFS_RESOURCE_WINDOW) != 0) {
			return nil;
		}
	}
	return self;
}

- (void)dealloc
{
	free(_window);
}

- (struct ntfs_environment)environment
{
	return (struct ntfs_environment){NTFS_API_VERSION, (__bridge void *)self, _size,
	    resource_read, resource_allocate, resource_release};
}

- (void *)allocateSize:(size_t)size
{
	void *bytes;

	@synchronized(self) {
		if (size == 0 || size > NTFS_CORE_MEMORY_LIMIT - _allocatedBytes) {
			return NULL;
		}
		bytes = malloc(size);
		if (bytes != NULL) {
			_allocatedBytes += size;
		}
		return bytes;
	}
}

- (void)releaseBytes:(void *)bytes size:(size_t)size
{
	@synchronized(self) {
		NSAssert(size <= _allocatedBytes, @"NTFS allocator accounting");
		_allocatedBytes -= size;
		free(bytes);
	}
}

- (enum ntfs_result)readAt:(uint64_t)offset bytes:(void *)buffer length:(size_t)length
{
	uint8_t *bytes = buffer;
	uint64_t start;
	size_t prefix, take, total, completed;
	NSError *error;

	@synchronized(self) {
		if (offset > _size || length > _size - offset || (length != 0 && buffer == NULL)) {
			return NTFS_IO;
		}
		while (length != 0) {
			start = offset - offset % _alignment;
			prefix = (size_t)(offset - start);
			take = MIN(length, NTFS_RESOURCE_WINDOW - prefix);
			total = (prefix + take + _alignment - 1) / _alignment * _alignment;
			if (total > _size - start) {
				return NTFS_IO;
			}
			error = nil;
			completed = [_reader readInto:_window
					   startingAt:(off_t)start
					       length:total
						error:&error];
			if (error != nil || completed != total) {
				return NTFS_IO;
			}
			memcpy(bytes, (uint8_t *)_window + prefix, take);
			bytes += take;
			offset += take;
			length -= take;
		}
	}
	return NTFS_OK;
}

@end

NSError *
ntfs_error(enum ntfs_result result)
{
	int code;

	if (result == NTFS_OK) {
		return nil;
	}
	switch (result) {
	case NTFS_NO_MEMORY:
		code = ENOMEM;
		break;
	case NTFS_NOT_FOUND:
		code = ENOENT;
		break;
	case NTFS_NOT_DIRECTORY:
		code = ENOTDIR;
		break;
	case NTFS_IS_DIRECTORY:
		code = EISDIR;
		break;
	case NTFS_INVALID:
		code = EINVAL;
		break;
	case NTFS_STALE:
		code = ESTALE;
		break;
	case NTFS_RANGE:
		code = EOVERFLOW;
		break;
	case NTFS_READ_ONLY:
		code = EROFS;
		break;
	case NTFS_UNSUPPORTED:
		code = ENOTSUP;
		break;
	case NTFS_BUSY:
		code = EBUSY;
		break;
	default:
		code = EIO;
		break;
	}
	return [NSError errorWithDomain:NSPOSIXErrorDomain
				   code:code
			       userInfo:@{
				       NSLocalizedDescriptionKey : @(ntfs_result_string(result))
			       }];
}

NSUUID *
ntfs_uuid(uint64_t serial)
{
	NSString *value = [NSString stringWithFormat:@"4d434c4e-%04llx-4e54-8f53-%012llx",
	    (unsigned long long)(serial >> NTFS_REFERENCE_SEQUENCE_SHIFT),
	    (unsigned long long)(serial & NTFS_REFERENCE_RECORD_MASK)];

	return [[NSUUID alloc] initWithUUIDString:value];
}

FSFileName *
ntfs_filename(const uint16_t *units, size_t length)
{
	char bytes[NTFS_UTF8_NAME_MAX];
	size_t count, i;

	for (i = 0; i < length; i++) {
		if (units[i] == 0 || units[i] == '/') {
			return nil;
		}
	}
	if (ntfs_utf16_to_utf8(units, length, bytes, sizeof(bytes), &count) != NTFS_OK) {
		return nil;
	}
	return [FSFileName nameWithBytes:bytes length:count];
}
