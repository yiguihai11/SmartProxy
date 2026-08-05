package engine

import (
	"sync"
	"testing"
)

// BenchmarkUDPDispatch_GoroutinePerPacket simulates the old implementation: a new goroutine is created to handle each UDP packet.
func BenchmarkUDPDispatch_GoroutinePerPacket(b *testing.B) {
	done := make(chan struct{}, b.N)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		go func() { done <- struct{}{} }()
	}
	for i := 0; i < b.N; i++ {
		<-done
	}
}

// BenchmarkUDPDispatch_WorkerPool simulates the new implementation: fixed workers + bounded queue delivery, with no goroutine creation.
func BenchmarkUDPDispatch_WorkerPool(b *testing.B) {
	jobs := make(chan struct{}, 128)
	var wg sync.WaitGroup
	for i := 0; i < udpWorkerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range jobs {
			}
		}()
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		jobs <- struct{}{}
	}
	close(jobs)
	wg.Wait()
}
