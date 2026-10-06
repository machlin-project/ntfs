/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#import "NTFSResource.h"
#include <ntfs/overwrite.h>

/* Private transport for an explicitly authorized ordinary image file. FSKit
 * passes the original URL and its security scope; no device path is inferred.
 * The caller excludes uncooperative access/mappings for the complete lifetime.
 * Advisory flock coordinates cooperating owners only. This component does not
 * admit a writable FSKit volume or claim exclusive ownership of arbitrary files.
 * All core/context users retain this object until their cleanup is complete. */
@interface NTFSImageTransport : NSObject
- (instancetype)initWithResource:(FSPathURLResource *)resource error:(NSError **)error;
/* Public path loading must require an actual sandbox scope before opening the
 * backing object. The unscoped initializer above is for local component owners. */
- (instancetype)initWithResource:(FSPathURLResource *)resource
	    requireSecurityScope:(BOOL)required
			   error:(NSError **)error;
- (struct ntfs_overwrite_environment)overwriteEnvironment;
/* Serialize a complete private owner operation, including the intervals between
 * transfers. Reader publication is excluded for its duration. The operation may
 * claim/release a private write owner, but cannot publish an immutable lease. */
- (enum ntfs_result)performExclusiveAccess:(enum ntfs_result (^)(void))operation;
/* Only a claimed transport can publish an immutable reader lease. The resource
 * uses the shared core allocation cap. Close every core child and release every
 * lease before mutation; write callbacks refuse without I/O while a lease lives.
 * Unclaim/revocation permanently invalidates existing leases. */
- (NTFSResource *)newReadResource;
- (void)invalidate;
@property(readonly, getter=isAvailable) BOOL available;
@property(readonly, getter=isClaimed) BOOL claimed;
/* Snapshot the opened image's native owner. These identities belong to the
 * authorized backing object, independently of NTFS Windows principals. */
@property(readonly) uid_t fileOwnerUserID;
@property(readonly) gid_t fileOwnerGroupID;
@end
