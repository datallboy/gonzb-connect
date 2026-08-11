package coordinator

import (
	"sync"
	"time"
)

type fixedWindowValue struct {
	started time.Time
	count   int
	bytes   int64
}

type fixedWindowLimiter struct {
	mu          sync.Mutex
	items       map[string]fixedWindowValue
	maxEntries  int
	lastCleanup time.Time
}

func newFixedWindowLimiter(maxEntries int) *fixedWindowLimiter {
	if maxEntries <= 0 {
		maxEntries = 65536
	}
	return &fixedWindowLimiter{items: make(map[string]fixedWindowValue), maxEntries: maxEntries}
}

func (l *fixedWindowLimiter) allow(key string, countLimit int, byteLimit, size int64, now time.Time) bool {
	if l == nil || key == "" || countLimit <= 0 || size < 0 {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.lastCleanup.IsZero() || now.Sub(l.lastCleanup) >= time.Minute {
		for itemKey, item := range l.items {
			if now.Sub(item.started) >= time.Minute {
				delete(l.items, itemKey)
			}
		}
		l.lastCleanup = now
	}
	item, exists := l.items[key]
	if !exists || now.Sub(item.started) >= time.Minute {
		if !exists && len(l.items) >= l.maxEntries {
			return false
		}
		item = fixedWindowValue{started: now}
	}
	if item.count >= countLimit || (byteLimit > 0 && size > byteLimit-item.bytes) {
		return false
	}
	item.count++
	item.bytes += size
	l.items[key] = item
	return true
}
