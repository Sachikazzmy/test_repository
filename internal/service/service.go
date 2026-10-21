// Package service validates records and coordinates bounded batch recognition.
package service

import (
	"context"
	"errors"
	"reflect"
	"sync"

	"bannerfingerprint/internal/contract"
)

type batchService struct {
	recognizer contract.Recognizer
	config     contract.ServiceConfig
}

type job struct {
	index  int
	record contract.Record
}

type jobResult struct {
	index          int
	identification contract.Identification
	err            error
}

// New creates a batch identifier with a validated, explicit configuration.
func New(recognizer contract.Recognizer, config contract.ServiceConfig) (contract.BatchIdentifier, error) {
	if recognizer == nil || isNilInterface(recognizer) {
		return nil, &contract.Error{Code: contract.CodeInvalidConfig, Message: "识别器不能为空"}
	}
	if err := contract.ValidateServiceConfig(config); err != nil {
		return nil, err
	}
	return &batchService{recognizer: recognizer, config: config}, nil
}

// IdentifyBatch validates and recognizes a batch while preserving input order.
// Invalid records and ordinary recognition failures are isolated to their own
// result. Cancellation and deadline errors abort the whole operation.
func (s *batchService) IdentifyBatch(ctx context.Context, records []contract.Record) ([]contract.Result, error) {
	if len(records) == 0 || len(records) > s.config.MaxBatchSize {
		return nil, &contract.Error{Code: contract.CodeInvalidBatch, Message: "批次数量不合法"}
	}
	if ctx == nil {
		return nil, &contract.Error{Code: contract.CodeInvalidConfig, Message: "请求上下文不能为空"}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	results := make([]contract.Result, len(records))
	valid := make([]job, 0, len(records))
	for i, record := range records {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		results[i] = newResult(i, record)
		if err := contract.ValidateRecord(record, s.config.MaxBannerBytes); err != nil {
			results[i].Status = contract.StatusInvalid
			results[i].Error = validationItemError(err)
			continue
		}
		valid = append(valid, job{index: i, record: record})
	}
	if len(valid) == 0 {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return results, nil
	}

	workerCount := s.config.Workers
	if workerCount > len(valid) {
		workerCount = len(valid)
	}
	workCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	jobs := make(chan job)
	completed := make(chan jobResult, len(valid))
	fatal := make(chan error, 1)
	var fatalOnce sync.Once
	var workers sync.WaitGroup
	workers.Add(workerCount)
	for range workerCount {
		go func() {
			defer workers.Done()
			for {
				select {
				case <-workCtx.Done():
					return
				case current, ok := <-jobs:
					if !ok {
						return
					}
					// A ready job and a canceled context may be selected together.
					// Check again before entering the recognizer.
					if workCtx.Err() != nil {
						return
					}
					identification, err := s.recognizer.Identify(workCtx, current.record)
					if isContextError(err) {
						fatalOnce.Do(func() {
							fatal <- err
							cancel()
						})
						return
					}
					completed <- jobResult{index: current.index, identification: identification, err: err}
				}
			}
		}()
	}

	sent := 0
	for _, current := range valid {
		select {
		case jobs <- current:
			sent++
		case <-workCtx.Done():
			close(jobs)
			workers.Wait()
			return nil, batchContextError(ctx, fatal, workCtx)
		}
	}
	close(jobs)

	for received := 0; received < sent; {
		select {
		case item := <-completed:
			results[item.index] = applyRecognition(results[item.index], item.identification, item.err)
			received++
		case <-workCtx.Done():
			workers.Wait()
			return nil, batchContextError(ctx, fatal, workCtx)
		}
	}
	workers.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := tryReceive(fatal); err != nil {
		return nil, err
	}
	return results, nil
}

func newResult(index int, record contract.Record) contract.Result {
	return contract.Result{
		Index:          index,
		IP:             record.IP,
		Port:           record.Port,
		Identification: contract.EmptyIdentification(),
	}
}

func validationItemError(err error) *contract.ItemError {
	var publicErr *contract.Error
	if errors.As(err, &publicErr) {
		return &contract.ItemError{Code: publicErr.Code, Message: publicErr.Message}
	}
	return &contract.ItemError{Code: contract.CodeInvalidRequest, Message: "输入记录不合法"}
}

func applyRecognition(result contract.Result, identification contract.Identification, err error) contract.Result {
	if err != nil {
		result.Status = contract.StatusFailed
		result.Error = &contract.ItemError{
			Code:    contract.CodeIdentificationFailed,
			Message: "指纹识别失败",
		}
		return result
	}
	if identification.Evidence == nil {
		identification.Evidence = []contract.Evidence{}
	}
	if identification.Candidates == nil {
		identification.Candidates = []contract.Candidate{}
	}
	for i := range identification.Candidates {
		if identification.Candidates[i].Evidence == nil {
			identification.Candidates[i].Evidence = []contract.Evidence{}
		}
	}
	result.Identification = identification
	if identification.Protocol != "" || identification.Product != "" {
		result.Status = contract.StatusMatched
	} else {
		result.Status = contract.StatusUnknown
	}
	return result
}

func isContextError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

func batchContextError(parent context.Context, fatal <-chan error, workCtx context.Context) error {
	if err := tryReceive(fatal); err != nil {
		return err
	}
	if err := parent.Err(); err != nil {
		return err
	}
	if err := workCtx.Err(); err != nil {
		return err
	}
	return context.Canceled
}

func tryReceive(ch <-chan error) error {
	select {
	case err := <-ch:
		return err
	default:
		return nil
	}
}

// isNilInterface catches typed nil implementations that would otherwise panic
// when their method is called.
func isNilInterface(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}
