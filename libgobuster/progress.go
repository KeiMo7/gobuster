package libgobuster

import "sync"

type MessageLevel int

const (
	LevelDebug MessageLevel = iota
	LevelInfo
	LevelWarn
	LevelError
)

type Message struct {
	Level   MessageLevel
	Message string
}

// FilterReason describes why a request was removed before becoming a result.
type FilterReason int

const (
	// FilterStatus means the response status code did not match the
	// configured include/exclude sets.
	FilterStatus FilterReason = iota
	// FilterLength means the response length matched an excluded length.
	FilterLength
	// FilterWildcard means the response matched the wildcard baseline.
	FilterWildcard
)

type Progress struct {
	requestsExpectedMutex *sync.RWMutex
	requestsExpected      int
	requestsCountMutex    *sync.RWMutex
	requestsIssued        int
	filteredMutex         *sync.RWMutex
	filteredStatus        int
	filteredLength        int
	filteredWildcard      int
	errorsMutex           *sync.RWMutex
	errorsCount           int
	ResultChan            chan Result
	ErrorChan             chan error
	MessageChan           chan Message
}

func NewProgress() *Progress {
	var p Progress
	p.requestsIssued = 0
	p.requestsExpectedMutex = new(sync.RWMutex)
	p.requestsCountMutex = new(sync.RWMutex)
	p.filteredMutex = new(sync.RWMutex)
	p.errorsMutex = new(sync.RWMutex)
	p.ResultChan = make(chan Result)
	p.ErrorChan = make(chan error)
	p.MessageChan = make(chan Message)
	return &p
}

func (p *Progress) RequestsExpected() int {
	p.requestsExpectedMutex.RLock()
	defer p.requestsExpectedMutex.RUnlock()
	return p.requestsExpected
}

func (p *Progress) RequestsIssued() int {
	p.requestsCountMutex.RLock()
	defer p.requestsCountMutex.RUnlock()
	return p.requestsIssued
}

func (p *Progress) incrementRequestsIssues(by int) {
	p.requestsCountMutex.Lock()
	defer p.requestsCountMutex.Unlock()
	p.requestsIssued += by
}

func (p *Progress) incrementRequests() {
	p.requestsCountMutex.Lock()
	defer p.requestsCountMutex.Unlock()
	p.requestsIssued++
}

func (p *Progress) IncrementTotalRequests(by int) {
	p.requestsExpectedMutex.Lock()
	defer p.requestsExpectedMutex.Unlock()
	p.requestsExpected += by
}

// IncrementFiltered records a request that was dropped by a plugin filter
// (status code, excluded length or wildcard). It never reaches ResultChan.
func (p *Progress) IncrementFiltered(reason FilterReason) {
	p.filteredMutex.Lock()
	defer p.filteredMutex.Unlock()
	switch reason {
	case FilterStatus:
		p.filteredStatus++
	case FilterLength:
		p.filteredLength++
	case FilterWildcard:
		p.filteredWildcard++
	}
}

// FilteredStatus returns the number of requests filtered by status code.
func (p *Progress) FilteredStatus() int {
	p.filteredMutex.RLock()
	defer p.filteredMutex.RUnlock()
	return p.filteredStatus
}

// FilteredLength returns the number of requests filtered by excluded length.
func (p *Progress) FilteredLength() int {
	p.filteredMutex.RLock()
	defer p.filteredMutex.RUnlock()
	return p.filteredLength
}

// FilteredWildcard returns the number of requests filtered as wildcard hits.
func (p *Progress) FilteredWildcard() int {
	p.filteredMutex.RLock()
	defer p.filteredMutex.RUnlock()
	return p.filteredWildcard
}

// FilteredTotal returns the total number of filtered requests across reasons.
func (p *Progress) FilteredTotal() int {
	p.filteredMutex.RLock()
	defer p.filteredMutex.RUnlock()
	return p.filteredStatus + p.filteredLength + p.filteredWildcard
}

// IncrementErrors records an error reported through ErrorChan.
func (p *Progress) IncrementErrors() {
	p.errorsMutex.Lock()
	defer p.errorsMutex.Unlock()
	p.errorsCount++
}

// ErrorsCount returns the number of errors reported through ErrorChan.
func (p *Progress) ErrorsCount() int {
	p.errorsMutex.RLock()
	defer p.errorsMutex.RUnlock()
	return p.errorsCount
}
