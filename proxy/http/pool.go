package http

import "sync"

//RequestPool pooling requests
type RequestPool struct {
	//pool for requests
	pool sync.Pool
}

//Acquire get a request from pool
func (r *RequestPool) Acquire() *Request {
	v := r.pool.Get()
	if v == nil {
		return &Request{}
	}
	return v.(*Request)
}

// Release put a request back into pool
func (r *RequestPool) Release(req *Request) {
	req.Reset()
	r.pool.Put(req)
}

//ResponsePool pooling responses
type ResponsePool struct {
	//pool for responses
	pool sync.Pool
}

//Acquire get a response from pool
func (r *ResponsePool) Acquire() *Response {
	v := r.pool.Get()
	if v == nil {
		return &Response{}
	}
	return v.(*Response)
}

// Release put a response back into pool
func (r *ResponsePool) Release(resp *Response) {
	resp.Reset()
	r.pool.Put(resp)
}
