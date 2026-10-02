/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#import "NTFSFileSystem.h"
#import "NTFSVolume.h"

@implementation NTFSFileSystem {
	NTFSVolume *_volume;
	FSResource *_resource;
}

- (void)probeResource:(FSResource *)resource
	 replyHandler:(void (^)(FSProbeResult *, NSError *))reply
{
	__attribute__((objc_precise_lifetime)) NTFSResource *owner;
	struct ntfs_environment env;
	struct ntfs_info info;
	enum ntfs_result result;

	if (![resource isKindOfClass:FSBlockDeviceResource.class]) {
		reply(FSProbeResult.notRecognizedProbeResult, nil);
		return;
	}
	owner = [[NTFSResource alloc] initWithReader:(id<NTFSBlockReader>)resource];
	if (owner == nil) {
		reply(nil, ntfs_error(NTFS_INVALID));
		return;
	}
	env = [owner environment];
	result = ntfs_probe(&env, &info);
	if (result == NTFS_NOT_NTFS) {
		reply(FSProbeResult.notRecognizedProbeResult, nil);
	} else if (result != NTFS_OK) {
		reply(nil, ntfs_error(result));
	} else {
		reply([FSProbeResult
			  usableProbeResultWithName:@"NTFS"
					containerID:[[FSContainerIdentifier alloc]
							initWithUUID:ntfs_uuid(info.serial)]],
		    nil);
	}
}

- (void)loadResource:(FSResource *)resource
	     options:(FSTaskOptions *)options
	replyHandler:(void (^)(FSVolume *, NSError *))reply
{
	__attribute__((objc_precise_lifetime)) NTFSResource *owner;
	NTFSVolume *loaded = nil;
	struct ntfs_environment env;
	struct ntfs_volume *core = NULL;
	struct ntfs_info info;
	NTFSLinkPolicy *policy;
	enum ntfs_result result = NTFS_OK;

	@synchronized(self) {
		if (_volume != nil) {
			result = NTFS_BUSY;
		} else if (![resource isKindOfClass:FSBlockDeviceResource.class]) {
			result = NTFS_UNSUPPORTED;
		} else {
			owner = [[NTFSResource alloc] initWithReader:(id<NTFSBlockReader>)resource];
			if (owner == nil) {
				result = NTFS_INVALID;
			} else {
				env = [owner environment];
				result = ntfs_mount(&env, NULL, &core);
				if (result == NTFS_OK) {
					ntfs_get_info(core, &info);
					result = ntfs_native_link_policy(
					    info.serial, options.taskOptions, &policy);
					if (result == NTFS_OK) {
						loaded = ntfs_volume_create_with_policy(
						    core, owner, policy);
					}
					if (loaded == nil) {
						(void)ntfs_unmount(core);
						if (result == NTFS_OK) {
							result = NTFS_IO;
						}
					} else {
						_volume = loaded;
						_resource = resource;
					}
				}
			}
		}
		self.containerStatus = result == NTFS_OK
		    ? FSContainerStatus.ready
		    : [FSContainerStatus blockedWithStatus:ntfs_error(result)];
	}
	reply(loaded, ntfs_error(result));
}

- (void)unloadResource:(FSResource *)resource
	       options:(FSTaskOptions *)options
	  replyHandler:(void (^)(NSError *))reply
{
	enum ntfs_result result = NTFS_OK;

	(void)options;
	@synchronized(self) {
		if (_resource != nil && _resource != resource) {
			result = NTFS_INVALID;
		} else {
			[_volume invalidate];
			_volume = nil;
			_resource = nil;
			self.containerStatus =
			    [FSContainerStatus notReadyWithStatus:ntfs_error(NTFS_STALE)];
		}
	}
	reply(ntfs_error(result));
}

@end
