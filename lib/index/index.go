package index

import "sync"

type StringIDIndex struct {
	mu   sync.RWMutex
	data map[string]int
}

func NewStringIDIndex(initialCapacity ...int) *StringIDIndex {
	var cap0 int
	if len(initialCapacity) > 0 && initialCapacity[0] > 0 {
		cap0 = initialCapacity[0]
	}
	idx := &StringIDIndex{}
	if cap0 > 0 {
		idx.data = make(map[string]int, cap0)
	} else {
		idx.data = make(map[string]int)
	}
	return idx
}

func (idx *StringIDIndex) Add(key string, id int) {
	idx.mu.Lock()
	idx.data[key] = id
	idx.mu.Unlock()
}

func (idx *StringIDIndex) Get(key string) (id int, ok bool) {
	idx.mu.RLock()
	id, ok = idx.data[key]
	idx.mu.RUnlock()
	return
}

func (idx *StringIDIndex) Remove(key string) {
	idx.mu.Lock()
	delete(idx.data, key)
	idx.mu.Unlock()
}

func (idx *StringIDIndex) Clear() {
	idx.mu.Lock()
	idx.data = make(map[string]int)
	idx.mu.Unlock()
}

type StringIndex struct {
	mu   sync.RWMutex
	data map[string]string
}

func NewStringIndex(initialCapacity ...int) *StringIndex {
	var cap0 int
	if len(initialCapacity) > 0 && initialCapacity[0] > 0 {
		cap0 = initialCapacity[0]
	}
	idx := &StringIndex{}
	if cap0 > 0 {
		idx.data = make(map[string]string, cap0)
	} else {
		idx.data = make(map[string]string)
	}
	return idx
}

func (idx *StringIndex) Add(key, value string) {
	idx.mu.Lock()
	idx.data[key] = value
	idx.mu.Unlock()
}

func (idx *StringIndex) Get(key string) (value string, ok bool) {
	idx.mu.RLock()
	value, ok = idx.data[key]
	idx.mu.RUnlock()
	return
}

func (idx *StringIndex) Remove(key string) {
	idx.mu.Lock()
	delete(idx.data, key)
	idx.mu.Unlock()
}

func (idx *StringIndex) Clear() {
	idx.mu.Lock()
	idx.data = make(map[string]string)
	idx.mu.Unlock()
}
