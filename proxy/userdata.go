package proxy

import (
	"io"
	"sync"
)

type dataKV struct {
	key   []byte
	value interface{}
}

// UserData user data
type UserData []dataKV

// Set sets key, value
func (d *UserData) Set(key string, value interface{}) {
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
func (d *UserData) Get(key string) interface{} {
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
func (d *UserData) Reset() {
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

// userDataPool pooling user data
type userDataPool struct{ pool sync.Pool }

// Acquire get a response from pool
func (r *userDataPool) Acquire() *UserData {
	v := r.pool.Get()
	if v == nil {
		return &UserData{}
	}
	return v.(*UserData)
}

// Release put a response back into pool
func (r *userDataPool) Release(data *UserData) {
	data.Reset()
	r.pool.Put(data)
}
