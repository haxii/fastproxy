package client

//RequestPool pooling http requests instances
type RequestPool interface {
	// Acquire returns an empty Request instance from Request Pool.
	//
	// The returned Request instance may be passed to Release() when it is
	// no longer needed. This allows Request recycling, reduces GC pressure
	// and usually improves performance.
	Acquire() Request
	// Release returns Request acquired via Acquire() to Request Pool.
	//
	// It is forbidden accessing req and/or its' members after returning
	// it to Request Pool.
	Release(Request)
}

//ResponsePool pooling http response instances
type ResponsePool interface {
	// Acquire returns an empty Response instance from Response Pool.
	//
	// The returned Response instance may be passed to Release() when it is
	// no longer needed. This allows Response recycling, reduces GC pressure
	// and usually improves performance.
	Acquire() Response
	// Release returns Response acquired via Acquire() to Response Pool.
	//
	// It is forbidden accessing req and/or its' members after returning
	// it to Response Pool.
	Release(Response)
}
