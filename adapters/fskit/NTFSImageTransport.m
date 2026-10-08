/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#import "NTFSImageTransport.h"
#include "../posix/overwrite_image.h"
#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>

@interface NTFSImageTransport ()
- (enum ntfs_result)claimImage;
- (void)unclaimImage;
- (BOOL)checkFile;
- (enum ntfs_result)readAt:(uint64_t)offset bytes:(void *)buffer length:(size_t)length;
- (enum ntfs_result)writeAt:(uint64_t)offset
		      bytes:(const void *)buffer
		     length:(size_t)length
		  completed:(size_t *)completed;
- (enum ntfs_result)persistImage;
- (void *)allocateSize:(size_t)size;
- (void)releaseBytes:(void *)bytes size:(size_t)size;
- (BOOL)retainReader:(uint64_t *)generation;
- (void)releaseReader;
- (BOOL)readerAvailable:(uint64_t)generation;
- (uint64_t)imageBytes;
- (void)finishTransfer;
/* Preserve and balance the original native scope; these narrow boundaries also
 * let component peers observe admission without claiming sandbox acceptance. */
- (BOOL)beginSecurityScopeForURL:(NSURL *)url;
- (void)endSecurityScopeForURL:(NSURL *)url;
/* Narrow native transfer boundaries permit fault injection without replacing
 * ownership, reader exclusion, revocation or poisoning in component tests. */
- (enum ntfs_result)transferWriteAt:(uint64_t)offset
			      bytes:(const void *)bytes
			     length:(size_t)length
			  completed:(size_t *)completed;
- (enum ntfs_result)transferPersist;
@end

static enum ntfs_result
native_image_claim(void *context)
{
	return [(__bridge NTFSImageTransport *)context claimImage];
}

static void
native_image_unclaim(void *context)
{
	[(__bridge NTFSImageTransport *)context unclaimImage];
}

static enum ntfs_result
native_image_read(void *context, uint64_t offset, void *bytes, size_t length)
{
	return [(__bridge NTFSImageTransport *)context readAt:offset bytes:bytes length:length];
}

static enum ntfs_result
native_image_write(
    void *context, uint64_t offset, const void *bytes, size_t length, size_t *completed)
{
	return [(__bridge NTFSImageTransport *)context writeAt:offset
							 bytes:bytes
							length:length
						     completed:completed];
}

static enum ntfs_result
native_image_persist(void *context)
{
	return [(__bridge NTFSImageTransport *)context persistImage];
}

static void *
native_image_allocate(void *context, size_t size)
{
	return [(__bridge NTFSImageTransport *)context allocateSize:size];
}

static void
native_image_release(void *context, void *bytes, size_t size)
{
	[(__bridge NTFSImageTransport *)context releaseBytes:bytes size:size];
}

@interface NTFSImageReader : NSObject <NTFSBlockReader>
- (instancetype)initWithTransport:(NTFSImageTransport *)transport;
@property(readonly) NTFSImageTransport *transport;
@end

@implementation NTFSImageReader {
	uint64_t _generation, _bytes;
	BOOL _leased;
}

- (instancetype)initWithTransport:(NTFSImageTransport *)transport
{
	self = [super init];
	if (self != nil) {
		_transport = transport;
		_leased = [transport retainReader:&_generation];
		if (!_leased) {
			return nil;
		}
		_bytes = [transport imageBytes];
	}
	return self;
}

- (void)dealloc
{
	if (_leased) {
		[_transport releaseReader];
	}
}

- (uint64_t)blockSize
{
	return NTFS_OVERWRITE_MIN_ALIGNMENT;
}

- (uint64_t)physicalBlockSize
{
	return self.blockSize;
}

- (uint64_t)blockCount
{
	return _bytes / self.blockSize;
}

- (BOOL)isRevoked
{
	return ![_transport readerAvailable:_generation];
}

- (size_t)readInto:(void *)buffer
	startingAt:(off_t)offset
	    length:(size_t)length
	     error:(NSError **)error
{
	enum ntfs_result result;

	result = offset < 0 || self.isRevoked ? NTFS_IO
					      : [_transport readAt:(uint64_t)offset
							     bytes:buffer
							    length:length];
	if (result == NTFS_OK && self.isRevoked) {
		result = NTFS_IO;
	}
	if (error != NULL) {
		*error = ntfs_error(result);
	}
	return result == NTFS_OK ? length : 0;
}

@end

/* The read-only environment keeps its existing shape and exact read budgets;
 * image and writer allocations share one live cap across view replacement. */
@interface NTFSImageReadResource : NTFSResource
- (instancetype)initWithImageReader:(NTFSImageReader *)reader;
@end

@implementation NTFSImageReadResource {
	NTFSImageTransport *_transport;
}

- (instancetype)initWithImageReader:(NTFSImageReader *)reader
{
	self = [super initWithReader:reader];
	if (self != nil) {
		_transport = reader.transport;
	}
	return self;
}

- (void *)allocateSize:(size_t)size
{
	return [_transport allocateSize:size];
}

- (void)releaseBytes:(void *)bytes size:(size_t)size
{
	[_transport releaseBytes:bytes size:size];
}

@end

@implementation NTFSImageTransport {
	FSPathURLResource *_resource;
	NSURL *_url;
	struct ntfs_overwrite_image _image;
	dev_t _device;
	ino_t _inode;
	uid_t _fileOwnerUserID;
	gid_t _fileOwnerGroupID;
	uint64_t _generation;
	NSUInteger _readers;
	size_t _allocatedBytes;
	BOOL _scoped, _busy, _exclusive, _unclaimPending;
}

- (instancetype)initWithResource:(FSPathURLResource *)resource error:(NSError **)error
{
	return [self initWithResource:resource requireSecurityScope:NO error:error];
}

- (instancetype)initWithResource:(FSPathURLResource *)resource
	    requireSecurityScope:(BOOL)required
			   error:(NSError **)error
{
	struct stat status;
	int result = EINVAL;

	self = [super init];
	if (self == nil) {
		result = ENOMEM;
	} else {
		_image.fd = -1;
		if ([resource isKindOfClass:FSPathURLResource.class] && !resource.isRevoked &&
		    resource.isWritable && resource.url.isFileURL) {
			_resource = resource;
			_url = resource.url;
			_scoped = [self beginSecurityScopeForURL:_url];
			if (required && !_scoped) {
				result = EACCES;
			} else if (resource.isRevoked) {
				result = EIO;
			} else {
				result = ntfs_overwrite_image_open(
				    _url.fileSystemRepresentation, &_image);
			}
			if (result == 0 && fstat(_image.fd, &status) != 0) {
				result = errno;
			}
			if (result == 0 &&
			    _image.environment.reader.size_bytes % NTFS_OVERWRITE_MIN_ALIGNMENT !=
				0) {
				result = EINVAL;
			}
			if (result == 0 && resource.isRevoked) {
				result = EIO;
			}
			if (result == 0) {
				_device = status.st_dev;
				_inode = status.st_ino;
				_fileOwnerUserID = status.st_uid;
				_fileOwnerGroupID = status.st_gid;
			}
		} else if ([resource isKindOfClass:FSPathURLResource.class] &&
		    !resource.isWritable) {
			result = EROFS;
		}
	}
	if (error != NULL) {
		*error = result == 0
		    ? nil
		    : [NSError errorWithDomain:NSPOSIXErrorDomain code:result userInfo:nil];
	}
	return result == 0 ? self : nil;
}

- (void)dealloc
{
	ntfs_overwrite_image_close(&_image);
	if (_scoped) {
		[self endSecurityScopeForURL:_url];
	}
}

- (BOOL)beginSecurityScopeForURL:(NSURL *)url
{
	return [url startAccessingSecurityScopedResource];
}

- (void)endSecurityScopeForURL:(NSURL *)url
{
	[url stopAccessingSecurityScopedResource];
}

- (struct ntfs_overwrite_environment)overwriteEnvironment
{
	return (struct ntfs_overwrite_environment){
	    {NTFS_API_VERSION, (__bridge void *)self, _image.environment.reader.size_bytes,
		native_image_read, native_image_allocate, native_image_release},
	    NTFS_OVERWRITE_API_VERSION, NTFS_OVERWRITE_MIN_ALIGNMENT, native_image_claim,
	    native_image_unclaim, native_image_write, native_image_persist};
}

- (BOOL)isAvailable
{
	@synchronized(self) {
		if (_resource.isRevoked) {
			_image.uncertain = true;
		}
		/* Cached native metadata and access checks also require the originally
		 * authorized backing object, even when no data transfer is needed. */
		return _image.fd >= 0 && !_image.uncertain && [self checkFile];
	}
}

- (BOOL)isClaimed
{
	@synchronized(self) {
		return _image.claimed;
	}
}

- (uid_t)fileOwnerUserID
{
	return _fileOwnerUserID;
}

- (gid_t)fileOwnerGroupID
{
	return _fileOwnerGroupID;
}

- (BOOL)checkFile
{
	struct stat file, path;

	if (_image.fd < 0 || _image.uncertain || _resource.isRevoked ||
	    fstat(_image.fd, &file) != 0 || lstat(_url.fileSystemRepresentation, &path) != 0 ||
	    !S_ISREG(file.st_mode) || !S_ISREG(path.st_mode) || file.st_nlink != 1 ||
	    file.st_size <= 0 || (uint64_t)file.st_size != _image.environment.reader.size_bytes ||
	    file.st_dev != _device || file.st_ino != _inode || path.st_dev != _device ||
	    path.st_ino != _inode || file.st_uid != _fileOwnerUserID ||
	    file.st_gid != _fileOwnerGroupID) {
		_image.uncertain = true;
		return NO;
	}
	return YES;
}

- (enum ntfs_result)claimImage
{
	enum ntfs_result result;

	@synchronized(self) {
		if (!self.isAvailable) {
			return NTFS_IO;
		}
		if (_busy || _image.claimed || _readers != 0) {
			return NTFS_BUSY;
		}
		if (_generation == UINT64_MAX || ![self checkFile]) {
			_image.uncertain = true;
			return NTFS_IO;
		}
		result = _image.environment.claim(&_image);
		if (result == NTFS_OK) {
			_generation++;
			if (![self checkFile]) {
				_image.environment.unclaim(&_image);
				return NTFS_IO;
			}
		}
		return result;
	}
}

- (void)unclaimImage
{
	@synchronized(self) {
		if (_busy) {
			/* A reentrant caller cannot release ownership underneath a native
			 * transfer. Finish the attempted I/O before releasing the lock. */
			_image.uncertain = true;
			_unclaimPending = YES;
		} else {
			_image.environment.unclaim(&_image);
		}
	}
}

- (void)finishTransfer
{
	_busy = NO;
	if (_unclaimPending) {
		_image.environment.unclaim(&_image);
		_unclaimPending = NO;
	}
}

- (enum ntfs_result)performExclusiveAccess:(enum ntfs_result (^)(void))operation
{
	@synchronized(self) {
		if (operation == nil) {
			return NTFS_INVALID;
		}
		if (!self.isAvailable) {
			return NTFS_IO;
		}
		if (_exclusive || _busy || _readers != 0) {
			return NTFS_BUSY;
		}
		_exclusive = YES;
		@try {
			return operation();
		} @finally {
			_exclusive = NO;
		}
	}
}

- (void)invalidate
{
	@synchronized(self) {
		_image.uncertain = true;
	}
}

- (uint64_t)imageBytes
{
	return _image.environment.reader.size_bytes;
}

- (BOOL)retainReader:(uint64_t *)generation
{
	@synchronized(self) {
		if (!_image.claimed || !self.isAvailable || _busy || _exclusive ||
		    _readers == NSUIntegerMax) {
			return NO;
		}
		_readers++;
		*generation = _generation;
		return YES;
	}
}

- (void)releaseReader
{
	@synchronized(self) {
		NSAssert(_readers != 0, @"NTFS image reader accounting");
		_readers--;
	}
}

- (BOOL)readerAvailable:(uint64_t)generation
{
	@synchronized(self) {
		return _image.claimed && self.isAvailable && generation == _generation;
	}
}

- (NTFSResource *)newReadResource
{
	NTFSImageReader *reader;

	@synchronized(self) {
		reader = [[NTFSImageReader alloc] initWithTransport:self];
		return reader == nil ? nil
				     : [[NTFSImageReadResource alloc] initWithImageReader:reader];
	}
}

- (void *)allocateSize:(size_t)size
{
	void *bytes;

	@synchronized(self) {
		/* The C owner reserves its own storage before attempting claim. Private
		 * allocation needs authorization/availability, but performs no media I/O. */
		if (!self.isAvailable || size == 0 ||
		    size > NTFS_CORE_MEMORY_LIMIT - _allocatedBytes) {
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
		NSAssert(size <= _allocatedBytes, @"NTFS image allocator accounting");
		_allocatedBytes -= size;
		free(bytes);
	}
}

- (enum ntfs_result)readAt:(uint64_t)offset bytes:(void *)bytes length:(size_t)length
{
	enum ntfs_result result;

	@synchronized(self) {
		if (!_image.claimed || !self.isAvailable) {
			return NTFS_IO;
		}
		if (_busy) {
			return NTFS_BUSY;
		}
		if ((length != 0 && bytes == NULL) || offset > [self imageBytes] ||
		    length > [self imageBytes] - offset) {
			return NTFS_INVALID;
		}
		if (![self checkFile]) {
			return NTFS_IO;
		}
		_busy = YES;
		@try {
			result = _image.environment.reader.read(&_image, offset, bytes, length);
			if (![self checkFile]) {
				result = NTFS_IO;
			}
		} @finally {
			[self finishTransfer];
		}
		return result;
	}
}

- (enum ntfs_result)transferWriteAt:(uint64_t)offset
			      bytes:(const void *)bytes
			     length:(size_t)length
			  completed:(size_t *)completed
{
	return _image.environment.write(&_image, offset, bytes, length, completed);
}

- (enum ntfs_result)writeAt:(uint64_t)offset
		      bytes:(const void *)bytes
		     length:(size_t)length
		  completed:(size_t *)completed
{
	enum ntfs_result result;

	if (completed == NULL) {
		return NTFS_INVALID;
	}
	*completed = 0;
	@synchronized(self) {
		if (!_image.claimed || !self.isAvailable) {
			return NTFS_IO;
		}
		if (_busy || _readers != 0) {
			return NTFS_BUSY;
		}
		if (bytes == NULL || length == 0 || length > NTFS_OVERWRITE_MAX_BYTES ||
		    offset % NTFS_OVERWRITE_MIN_ALIGNMENT != 0 ||
		    length % NTFS_OVERWRITE_MIN_ALIGNMENT != 0 || offset > [self imageBytes] ||
		    length > [self imageBytes] - offset) {
			return NTFS_INVALID;
		}
		if (![self checkFile]) {
			return NTFS_IO;
		}
		_busy = YES;
		@try {
			result = [self transferWriteAt:offset
						 bytes:bytes
						length:length
					     completed:completed];
			if (result != NTFS_OK || *completed != length || ![self checkFile]) {
				_image.uncertain = true;
				result = NTFS_IO;
			}
		} @finally {
			[self finishTransfer];
		}
		return result;
	}
}

- (enum ntfs_result)transferPersist
{
	return _image.environment.persist(&_image);
}

- (enum ntfs_result)persistImage
{
	enum ntfs_result result;

	@synchronized(self) {
		if (!_image.claimed || !self.isAvailable || ![self checkFile]) {
			return NTFS_IO;
		}
		if (_busy) {
			return NTFS_BUSY;
		}
		_busy = YES;
		@try {
			result = [self transferPersist];
			if (result != NTFS_OK || ![self checkFile]) {
				_image.uncertain = true;
				result = NTFS_IO;
			}
		} @finally {
			[self finishTransfer];
		}
		return result;
	}
}

@end
