/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#import "NTFSResource.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>

static enum ntfs_result
native_resource_read(void *context, uint64_t offset, void *buffer, size_t length)
{
	return [(__bridge NTFSResource *)context readAt:offset bytes:buffer length:length];
}

static void *
native_resource_allocate(void *context, size_t size)
{
	return [(__bridge NTFSResource *)context allocateSize:size];
}

static void
native_resource_release(void *context, void *buffer, size_t size)
{
	[(__bridge NTFSResource *)context releaseBytes:buffer size:size];
}

@interface NTFSResource ()
- (enum ntfs_result)chargeRead:(size_t)size;
@end

@implementation NTFSResource {
	id<NTFSBlockReader> _reader;
	uint64_t _size;
	size_t _alignment;
	void *_window;
	size_t _allocatedBytes;
	BOOL _revoked;
	BOOL _reading;
	struct ntfs_resource_read_budget *_readBudget;
	NSUInteger _readBudgetDepth;
}

- (instancetype)initWithReader:(id<NTFSBlockReader>)reader
{
	uint64_t block, count, alignment;

	if (reader == nil || reader.isRevoked) {
		return nil;
	}
	block = reader.blockSize;
	count = reader.blockCount;
	alignment = MAX(reader.physicalBlockSize, block);
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

- (BOOL)isAvailable
{
	@synchronized(self) {
		if (_reader.isRevoked) {
			_revoked = YES;
		}
		return !_revoked;
	}
}

- (struct ntfs_environment)environment
{
	return (struct ntfs_environment){NTFS_API_VERSION, (__bridge void *)self, _size,
	    native_resource_read, native_resource_allocate, native_resource_release};
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
	void *destination;
	NSError *error;
	BOOL direct;
	enum ntfs_result result;

	@synchronized(self) {
		if (!self.isAvailable || offset > _size || length > _size - offset ||
		    (length != 0 && buffer == NULL)) {
			return NTFS_IO;
		}
		if (_reading) {
			return NTFS_BUSY;
		}
		_reading = YES;
		@try {
			while (length != 0) {
				if (!self.isAvailable) {
					return NTFS_IO;
				}
				start = offset - offset % _alignment;
				prefix = (size_t)(offset - start);
				take = MIN(length, NTFS_RESOURCE_WINDOW - prefix);
				total = (prefix + take + _alignment - 1) / _alignment * _alignment;
				if (total > _size - start) {
					return NTFS_IO;
				}
				/* Transfer only the requested caller span. Unaligned addresses,
				 * disk offsets and partial final sectors keep the bounded private
				 * window. */
				direct = prefix == 0 && take == total &&
				    (uintptr_t)bytes % _alignment == 0;
				destination = direct ? bytes : _window;
				result = [self chargeRead:total];
				if (result != NTFS_OK) {
					return result;
				}
				error = nil;
				completed = [_reader readInto:destination
						   startingAt:(off_t)start
						       length:total
							error:&error];
				if (error != nil || completed != total || !self.isAvailable) {
					return NTFS_IO;
				}
				if (!direct) {
					memcpy(bytes, (uint8_t *)_window + prefix, take);
				}
				bytes += take;
				offset += take;
				length -= take;
			}
		} @finally {
			_reading = NO;
		}
	}
	return NTFS_OK;
}

- (enum ntfs_result)beginReadBudget:(struct ntfs_resource_read_budget *)budget
			     limits:(const struct ntfs_operation_limits *)limits
{
	@synchronized(self) {
		if (budget == NULL || limits == NULL || limits->read_calls == 0 ||
		    limits->read_bytes == 0) {
			return NTFS_INVALID;
		}
		if (_reading || budget->active || _readBudgetDepth == NTFS_OPERATION_MAX_DEPTH) {
			return NTFS_BUSY;
		}
		if ([self readBudgetResult] != NTFS_OK) {
			return NTFS_RANGE;
		}
		memset(budget, 0, sizeof(*budget));
		budget->max_calls = limits->read_calls;
		budget->max_bytes = limits->read_bytes;
		budget->previous = _readBudget;
		budget->active = YES;
		_readBudget = budget;
		_readBudgetDepth++;
		return NTFS_OK;
	}
}

- (enum ntfs_result)endReadBudget:(struct ntfs_resource_read_budget *)budget
{
	@synchronized(self) {
		if (budget == NULL || !budget->active) {
			return NTFS_INVALID;
		}
		if (_reading || _readBudget != budget) {
			return NTFS_BUSY;
		}
		_readBudget = budget->previous;
		_readBudgetDepth--;
		budget->previous = NULL;
		budget->active = NO;
		return NTFS_OK;
	}
}

- (enum ntfs_result)readBudgetResult
{
	struct ntfs_resource_read_budget *budget;

	@synchronized(self) {
		for (budget = _readBudget; budget != NULL; budget = budget->previous) {
			if (budget->exhausted != NTFS_OPERATION_LIMIT_NONE) {
				return NTFS_RANGE;
			}
		}
		return NTFS_OK;
	}
}

- (enum ntfs_result)chargeRead:(size_t)size
{
	struct ntfs_resource_read_budget *budget;
	enum ntfs_operation_limit exhausted = NTFS_OPERATION_LIMIT_NONE;

	/* The exact-read monitor owns this short accounting step and remains held
	 * through the synchronous callback. No refused fragment reaches the reader. */
	if ([self readBudgetResult] != NTFS_OK) {
		return NTFS_RANGE;
	}
	for (budget = _readBudget; budget != NULL; budget = budget->previous) {
		if (budget->calls == budget->max_calls) {
			exhausted = NTFS_OPERATION_LIMIT_READ_CALLS;
			break;
		}
		if (size > budget->max_bytes - budget->bytes) {
			exhausted = NTFS_OPERATION_LIMIT_READ_BYTES;
			break;
		}
	}
	if (exhausted != NTFS_OPERATION_LIMIT_NONE) {
		for (budget = _readBudget; budget != NULL; budget = budget->previous) {
			budget->exhausted = exhausted;
		}
		return NTFS_RANGE;
	}
	for (budget = _readBudget; budget != NULL; budget = budget->previous) {
		budget->calls++;
		budget->bytes += size;
	}
	return NTFS_OK;
}

@end

NSError *
ntfs_native_result_error(id result, NSError *error)
{
	return error != nil ? error : result == nil ? ntfs_error(NTFS_IO) : nil;
}

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
	case NTFS_NO_SPACE:
		code = ENOSPC;
		break;
	case NTFS_EXISTS:
		code = EEXIST;
		break;
	case NTFS_NOT_EMPTY:
		code = ENOTEMPTY;
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
	case NTFS_TOO_MANY_LINKS:
		code = ELOOP;
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
