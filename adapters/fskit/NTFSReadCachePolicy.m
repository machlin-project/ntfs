/* Copyright (c) 2026 Dmitri Arekhta. All rights reserved. */
#import "NTFSReadCachePolicy.h"

@implementation NTFSReadCachePolicy {
	dispatch_source_t _source;
	NSObject *_sourceIdentity;
	BOOL _running, _raised;
}

- (void)dealloc
{
	[self stop];
}

- (dispatch_source_t)newPressureSource
{
	return dispatch_source_create(DISPATCH_SOURCE_TYPE_MEMORYPRESSURE, 0,
	    DISPATCH_MEMORYPRESSURE_NORMAL | DISPATCH_MEMORYPRESSURE_WARN |
		DISPATCH_MEMORYPRESSURE_CRITICAL,
	    dispatch_get_global_queue(QOS_CLASS_UTILITY, 0));
}

- (void)start
{
	__weak NTFSReadCachePolicy *weakSelf = self;
	NSObject *identity;

	@synchronized(self) {
		if (_running) {
			return;
		}
		_running = YES;
		_source = [self newPressureSource];
		if (_source == nil) {
			/* An unavailable observer must not enable optional retention. */
			_raised = YES;
			return;
		}
		identity = [[NSObject alloc] init];
		if (identity == nil) {
			_raised = YES;
			dispatch_resume(_source);
			dispatch_source_cancel(_source);
			_source = nil;
			return;
		}
		_sourceIdentity = identity;
		dispatch_source_set_event_handler(_source, ^{
		  NTFSReadCachePolicy *policy = weakSelf;

		  if (policy == nil) {
			  return;
		  }
		  @synchronized(policy) {
			  /* A queued callback from a canceled source cannot affect a new
			   * observation interval, even after an immediate remount. */
			  if (policy->_sourceIdentity == identity && policy->_source != nil) {
				  [policy applyPressure:dispatch_source_get_data(policy->_source)];
			  }
		  }
		});
		dispatch_resume(_source);
	}
}

- (void)stop
{
	@synchronized(self) {
		_running = NO;
		_sourceIdentity = nil;
		if (_source != nil) {
			dispatch_source_cancel(_source);
			_source = nil;
		}
	}
}

- (void)applyPressure:(dispatch_source_memorypressure_flags_t)flags
{
	@synchronized(self) {
		if (!_running) {
			return;
		}
		/* Coalesced elevated levels outrank NORMAL. Zero and unknown bits do
		 * not restore caching. Keep the last observed level across remount. */
		if ((flags & (DISPATCH_MEMORYPRESSURE_WARN | DISPATCH_MEMORYPRESSURE_CRITICAL)) !=
		    0) {
			_raised = YES;
		} else if ((flags & DISPATCH_MEMORYPRESSURE_NORMAL) != 0 && _source != nil) {
			_raised = NO;
		}
	}
}

- (BOOL)retentionActive
{
	@synchronized(self) {
		return _running && _source != nil && !_raised;
	}
}

@end
