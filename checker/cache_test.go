package checker

import (
	"testing"
	"time"
)

func TestSimpleCacheMap(t *testing.T) {
	cache := CreateSimpleCache(time.Hour)
	err := cache.PutHostnameScan("anything", HostnameResult{Status: 3})
	if err != nil {
		t.Errorf("Expected scan put to succeed: %v", err)
	}
	result, err := cache.GetHostnameScan("anything")
	if err != nil {
		t.Errorf("Expected scan get to succeed: %v", err)
	}
	if result.Status != 3 {
		t.Errorf("Expected scan to have status 3, had status %d", result.Status)
	}
}

func TestSimpleCacheExpires(t *testing.T) {
	cache := CreateSimpleCache(0)
	cache.PutHostnameScan("anything", HostnameResult{Status: 3})
	_, err := cache.GetHostnameScan("anything")
	if err == nil {
		t.Errorf("Expected cache to expire and scan get to fail: %v", err)
	}
}
