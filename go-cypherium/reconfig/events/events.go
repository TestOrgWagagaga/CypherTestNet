package events

import (
	"github.com/dedis/onet/log"
)

func init() {
}

type Event interface{}

type Receiver interface {
	ProcessEvent(e Event) Event
}

type threaded struct {
	exit chan struct{}
}

func (t *threaded) Halt() {
	select {
	case <-t.exit:
		log.Lvl1("Attempted to halt a threaded object twice")
	default:
		close(t.exit)
	}
}

type Manager interface {
	Inject(Event)         // A temporary interface to allow the event manager thread to skip the queue
	Queue() chan<- Event  // Get a write-only reference to the queue, to submit events
	SetReceiver(Receiver) // Set the target to route events to
	Start()               // Starts the Manager thread TODO, these thread management things should probably go away
	Halt()                // Stops the Manager thread
}

// managerImpl is an implementation of Manger
type managerImpl struct {
	threaded
	receiver Receiver
	events   chan Event
}

// NewManagerImpl creates an instance of managerImpl
func NewManagerImpl() Manager {
	return &managerImpl{
		events:   make(chan Event),
		threaded: threaded{make(chan struct{})},
	}
}

// SetReceiver sets the destination for events
func (em *managerImpl) SetReceiver(receiver Receiver) {
	em.receiver = receiver
}

// Start creates the go routine necessary to deliver events
func (em *managerImpl) Start() {
	go em.eventLoop()
}

// queue returns a write only reference to the event queue
func (em *managerImpl) Queue() chan<- Event {
	log.Lvl5("Queue()")
	return em.events
}

// SendEvent performs the event loop on a receiver to completion
func SendEvent(receiver Receiver, event Event) {
	next := event
	for {
		// If an event returns something non-nil, then process it as a new event
		log.Lvl5("SendEvent")
		next = receiver.ProcessEvent(next)
		if next == nil {
			break
		}
	}
}

// Inject can only safely be called by the managerImpl thread itself, it skips the queue
func (em *managerImpl) Inject(event Event) {
	if em.receiver != nil {
		SendEvent(em.receiver, event)
	}
}

// eventLoop is where the event thread loops, delivering events
func (em *managerImpl) eventLoop() {
	for {
		log.Lvl5("eventLoop")
		select {
		case next := <-em.events:
			em.Inject(next)
		case <-em.exit:
			log.Lvl3("eventLoop told to exit")
			return
		}
	}
}
