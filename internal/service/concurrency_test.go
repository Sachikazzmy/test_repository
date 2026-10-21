package service

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"bannerfingerprint/internal/contract"
)

func TestIdentifyBatchRestoresInputOrderAfterOutOfOrderCompletion(t *testing.T) {
	const count = 4
	started := make(chan int, count)
	finished := make(chan int, count)
	release := make([]chan struct{}, count)
	for i := range release {
		release[i] = make(chan struct{})
	}
	var mu sync.Mutex
	active, peak := 0, 0
	recognizer := identifyFunc(func(_ context.Context, record contract.Record) (contract.Identification, error) {
		var index int
		if _, err := fmt.Sscanf(record.Banner, "item-%d", &index); err != nil {
			return contract.Identification{}, err
		}
		mu.Lock()
		active++
		if active > peak {
			peak = active
		}
		mu.Unlock()
		started <- index
		<-release[index]
		mu.Lock()
		active--
		mu.Unlock()
		finished <- index
		id := contract.EmptyIdentification()
		id.Product = record.Banner
		return id, nil
	})
	config := contract.ServiceConfig{MaxBatchSize: count, MaxBannerBytes: 32, Workers: count}
	service, err := New(recognizer, config)
	if err != nil {
		t.Fatal(err)
	}
	input := make([]contract.Record, count)
	for i := range input {
		input[i] = contract.Record{IP: fmt.Sprintf("198.51.100.%d", i+1), Port: 80, Banner: fmt.Sprintf("item-%d", i)}
	}
	type outcome struct {
		results []contract.Result
		err     error
	}
	done := make(chan outcome, 1)
	go func() {
		results, err := service.IdentifyBatch(context.Background(), input)
		done <- outcome{results: results, err: err}
	}()
	for i := 0; i < count; i++ {
		<-started
	}
	// Release in reverse order; output order must still match input order.
	for i := count - 1; i >= 0; i-- {
		close(release[i])
		if finishedIndex := <-finished; finishedIndex != i {
			t.Fatalf("finished item %d after releasing %d", finishedIndex, i)
		}
	}
	got := <-done
	if got.err != nil {
		t.Fatal(got.err)
	}
	for i, result := range got.results {
		if result.Index != i || result.Product != input[i].Banner {
			t.Errorf("result[%d] = (index %d, product %q), want (%d, %q)", i, result.Index, result.Product, i, input[i].Banner)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if peak > count || peak != count {
		t.Errorf("peak calls = %d, want %d", peak, count)
	}
}

func TestIdentifyBatchEnforcesWorkerLimit(t *testing.T) {
	const workers = 2
	const recordsCount = 5
	started := make(chan struct{}, recordsCount)
	release := make(chan struct{})
	var mu sync.Mutex
	active, peak := 0, 0
	recognizer := identifyFunc(func(context.Context, contract.Record) (contract.Identification, error) {
		mu.Lock()
		active++
		if active > peak {
			peak = active
		}
		mu.Unlock()
		started <- struct{}{}
		<-release
		mu.Lock()
		active--
		mu.Unlock()
		return contract.EmptyIdentification(), nil
	})
	config := contract.ServiceConfig{MaxBatchSize: recordsCount, MaxBannerBytes: 32, Workers: workers}
	service, err := New(recognizer, config)
	if err != nil {
		t.Fatal(err)
	}
	input := make([]contract.Record, recordsCount)
	for i := range input {
		input[i] = contract.Record{IP: fmt.Sprintf("203.0.113.%d", i+1), Port: 80, Banner: "ok"}
	}
	done := make(chan error, 1)
	go func() {
		_, err := service.IdentifyBatch(context.Background(), input)
		done <- err
	}()
	<-started
	<-started
	mu.Lock()
	gotPeak := peak
	mu.Unlock()
	if gotPeak != workers {
		t.Fatalf("peak calls before release = %d, want %d", gotPeak, workers)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if peak != workers {
		t.Errorf("peak calls = %d, want %d", peak, workers)
	}
}

func TestIdentifyBatchCancellationStopsDispatchAndJoinsWorkers(t *testing.T) {
	const workers = 2
	const recordsCount = 8
	started := make(chan struct{}, recordsCount)
	exited := make(chan struct{}, recordsCount)
	var mu sync.Mutex
	calls := 0
	recognizer := identifyFunc(func(ctx context.Context, _ contract.Record) (contract.Identification, error) {
		mu.Lock()
		calls++
		mu.Unlock()
		started <- struct{}{}
		<-ctx.Done()
		exited <- struct{}{}
		return contract.Identification{}, ctx.Err()
	})
	config := contract.ServiceConfig{MaxBatchSize: recordsCount, MaxBannerBytes: 32, Workers: workers}
	service, err := New(recognizer, config)
	if err != nil {
		t.Fatal(err)
	}
	input := make([]contract.Record, recordsCount)
	for i := range input {
		input[i] = contract.Record{IP: fmt.Sprintf("192.0.2.%d", i+1), Port: 80, Banner: "ok"}
	}
	ctx, cancel := context.WithCancel(context.Background())
	type outcome struct {
		results []contract.Result
		err     error
	}
	done := make(chan outcome, 1)
	go func() {
		results, err := service.IdentifyBatch(ctx, input)
		done <- outcome{results: results, err: err}
	}()
	<-started
	<-started
	cancel()
	got := <-done
	if got.err != context.Canceled {
		t.Fatalf("IdentifyBatch error = %v, want context.Canceled", got.err)
	}
	if got.results != nil {
		t.Fatalf("canceled request returned partial results: %#v", got.results)
	}
	mu.Lock()
	gotCalls := calls
	mu.Unlock()
	if gotCalls > workers {
		t.Fatalf("recognizer calls after cancellation = %d, want at most %d", gotCalls, workers)
	}
	for i := 0; i < gotCalls; i++ {
		<-exited
	}
}
