package userdata

import (
	"io"
	"sync"
)

type dataKV struct {
	key   []byte
	value interface{}
}

// Data user data
type Data []dataKV

// Set sets key, value
func (d *Data) Set(key string, value interface{}) {
	args := *d
	n := len(args)
	for i := 0; i < n; i++ {
		kv := &args[i]
		if string(kv.key) == key {
			kv.value = value
			return
		}
	}

	c := cap(args)
	if c > n {
		args = args[:n+1]
		kv := &args[n]
		kv.key = append(kv.key[:0], key...)
		kv.value = value
		*d = args
		return
	}

	kv := dataKV{}
	kv.key = append(kv.key[:0], key...)
	kv.value = value
	*d = append(args, kv)
}

// Get gets value of key
func (d *Data) Get(key string) interface{} {
	args := *d
	n := len(args)
	for i := 0; i < n; i++ {
		kv := &args[i]
		if string(kv.key) == key {
			return kv.value
		}
	}
	return nil
}

// Reset resets user data
func (d *Data) Reset() {
	args := *d
	n := len(args)
	for i := 0; i < n; i++ {
		v := args[i].value
		if vc, ok := v.(io.Closer); ok {
			vc.Close()
		}
	}
	*d = (*d)[:0]
}

// Pool pooling user data
type Pool struct{ pool sync.Pool }

// Acquire get a response from pool
func (r *Pool) Acquire() *Data {
	v := r.pool.Get()
	if v == nil {
		return &Data{}
	}
	return v.(*Data)
}

// Release put a response back into pool
func (r *Pool) Release(data *Data) {
	data.Reset()
	r.pool.Put(data)
}
