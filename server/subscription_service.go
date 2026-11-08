package server

import (
	"context"
	"sync"
	"time"

	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/uasc"
)

// maxRetainedNotifications is the maximum number of sent but unacknowledged
// notification messages a subscription keeps for retransmission. When the
// limit is exceeded the message with the smallest sequence number is
// discarded, as required by OPC UA Part 4 (the retransmission queue).
const maxRetainedNotifications = 100

// SubscriptionService implements the Subscription Service Set.
//
// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.13
type SubscriptionService struct {
	srv *Server
	// pub sub stuff
	Mu   sync.Mutex
	Subs map[uint32]*Subscription
}

// get rid of all references to a subscription and all monitored items that are pointed at this subscription.
func (s *SubscriptionService) DeleteSubscription(id uint32) {
	s.Mu.Lock()
	sub, ok := s.Subs[id]
	if ok {
		sub.Mu.Lock()
		if sub.running {
			sub.running = false
			close(sub.shutdown)
		}
		sub.Mu.Unlock()
	}
	delete(s.Subs, id)
	s.Mu.Unlock()

	if !ok {
		return
	}

	// Purge the monitored items outside of the service lock: the monitored
	// item service takes the lock in the opposite direction (its create path
	// holds its own lock and then briefly takes this one), so calling it here
	// would invert the lock order.
	s.srv.MonitoredItemService.DeleteSub(id)
}

// deleteSubscriptionsOfSession deletes every subscription owned by sess
// together with its monitored items. Subscriptions owned by other sessions
// are left untouched. It implements the DeleteSubscriptions=true behaviour of
// CloseSession (Part 4, 5.6.4).
func (s *SubscriptionService) deleteSubscriptionsOfSession(sess *session) {
	if sess == nil {
		return
	}

	s.Mu.Lock()
	ids := make([]uint32, 0)
	for id, sub := range s.Subs {
		if sub.ownedBy(sess) {
			ids = append(ids, id)
		}
	}
	s.Mu.Unlock()

	for _, id := range ids {
		if s.srv.cfg.logger != nil {
			s.srv.cfg.logger.Info("Subscription %d deleted with session %v", id, sess.AuthTokenID)
		}
		s.DeleteSubscription(id)
	}
}

// detachSubscriptionsOfSession removes the session as the owner of its
// subscriptions without deleting them or their monitored items. Detached
// subscriptions keep collecting notifications and can be taken over by
// another session via TransferSubscriptions. It implements the
// DeleteSubscriptions=false behaviour of CloseSession (Part 4, 5.6.4).
func (s *SubscriptionService) detachSubscriptionsOfSession(sess *session) {
	if sess == nil {
		return
	}

	s.Mu.Lock()
	subs := make([]*Subscription, 0)
	for _, sub := range s.Subs {
		if sub.ownedBy(sess) {
			subs = append(subs, sub)
		}
	}
	s.Mu.Unlock()

	for _, sub := range subs {
		sub.setOwner(nil, nil)
		sub.signalOwner()
	}

	// Drop the publish requests that were queued on the closed session so that
	// nobody answers them on the dead secure channel once the subscriptions
	// have been detached.
	drainPublishRequests(sess)
}

// drainPublishRequests removes and discards every publish request currently
// queued for a session.
func drainPublishRequests(sess *session) {
	for {
		select {
		case <-sess.PublishRequests:
		default:
			return
		}
	}
}

// processAcknowledgements applies the acknowledgements carried by a
// PublishRequest and returns one result per acknowledgement, in order:
//
//   - Good when the named message was removed from the subscription's
//     retransmission queue,
//   - Bad_SequenceNumberUnknown when the subscription exists but does not
//     hold (anymore) the named sequence number,
//   - Bad_SubscriptionIdInvalid when the named subscription does not exist.
//
// An acknowledgement only touches the subscription it names.
func (s *SubscriptionService) processAcknowledgements(acks []*ua.SubscriptionAcknowledgement) []ua.StatusCode {
	results := make([]ua.StatusCode, len(acks))
	for i, ack := range acks {
		if ack == nil {
			results[i] = ua.StatusBadSequenceNumberUnknown
			continue
		}

		s.Mu.Lock()
		sub, ok := s.Subs[ack.SubscriptionID]
		s.Mu.Unlock()
		if !ok {
			results[i] = ua.StatusBadSubscriptionIDInvalid
			continue
		}
		results[i] = sub.ackMessage(ack.SequenceNumber)
	}
	return results
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.13.2
func (s *SubscriptionService) CreateSubscription(sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	if s.srv.cfg.logger != nil {
		s.srv.cfg.logger.Debug("Handling %T", r)
	}

	req, err := safeReq[*ua.CreateSubscriptionRequest](r)
	if err != nil {
		return nil, err
	}

	s.Mu.Lock()
	defer s.Mu.Unlock()

	newsubid := uint32(len(s.Subs)) + 1

	if s.srv.cfg.logger != nil {
		s.srv.cfg.logger.Info("New Sub %d for %v", newsubid, sc.RemoteAddr())
	}

	sub := NewSubscription()
	sub.srv = s
	sub.setOwner(s.srv.Session(r.Header()), sc)
	sub.ID = newsubid
	sub.RevisedPublishingInterval = req.RequestedPublishingInterval
	sub.RevisedLifetimeCount = req.RequestedLifetimeCount
	sub.RevisedMaxKeepAliveCount = req.RequestedMaxKeepAliveCount

	s.Subs[newsubid] = sub
	sub.Mu.Lock()
	sub.running = true
	sub.Mu.Unlock()
	sub.Start()

	resp := &ua.CreateSubscriptionResponse{
		ResponseHeader: &ua.ResponseHeader{
			Timestamp:          time.Now(),
			RequestHandle:      req.RequestHeader.RequestHandle,
			ServiceResult:      ua.StatusOK,
			ServiceDiagnostics: &ua.DiagnosticInfo{},
			StringTable:        []string{},
			AdditionalHeader:   ua.NewExtensionObject(nil),
		},
		SubscriptionID:            uint32(newsubid),
		RevisedPublishingInterval: req.RequestedPublishingInterval,
		RevisedLifetimeCount:      req.RequestedLifetimeCount,
		RevisedMaxKeepAliveCount:  req.RequestedMaxKeepAliveCount,
	}
	return resp, nil
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.13.3
func (s *SubscriptionService) ModifySubscription(sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	if s.srv.cfg.logger != nil {
		s.srv.cfg.logger.Debug("Handling %T", r)
	}

	req, err := safeReq[*ua.ModifySubscriptionRequest](r)
	if err != nil {
		return nil, err
	}

	// When this gets implemented, be sure to check the subscription session vs the request session!

	return serviceUnsupported(req.RequestHeader), nil
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.13.4
func (s *SubscriptionService) SetPublishingMode(sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	if s.srv.cfg.logger != nil {
		s.srv.cfg.logger.Debug("Handling %T", r)
	}

	req, err := safeReq[*ua.SetPublishingModeRequest](r)
	if err != nil {
		return nil, err
	}
	// When this gets implemented, be sure to check the subscription session vs the request session!
	return serviceUnsupported(req.RequestHeader), nil
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.13.5
func (s *SubscriptionService) Publish(sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	if s.srv.cfg.logger != nil {
		s.srv.cfg.logger.Debug("Raw Publish req")
	}

	req, err := safeReq[*ua.PublishRequest](r)
	if err != nil {
		if s.srv.cfg.logger != nil {
			s.srv.cfg.logger.Error("ERROR: bad PublishRequest Struct")
		}
		return nil, err
	}

	session := s.srv.Session(req.RequestHeader)

	if session == nil {
		response := &ua.PublishResponse{
			ResponseHeader: &ua.ResponseHeader{
				Timestamp:          time.Now(),
				RequestHandle:      req.RequestHeader.RequestHandle,
				ServiceResult:      ua.StatusBadSessionIDInvalid,
				ServiceDiagnostics: &ua.DiagnosticInfo{},
				StringTable:        []string{},
				AdditionalHeader:   ua.NewExtensionObject(nil),
			},
			SubscriptionID:           0,
			MoreNotifications:        false,
			NotificationMessage:      &ua.NotificationMessage{NotificationData: []*ua.ExtensionObject{}},
			AvailableSequenceNumbers: []uint32{},
			Results:                  []ua.StatusCode{},
			DiagnosticInfos:          []*ua.DiagnosticInfo{},
		}

		return response, nil
	}

	pubreq := PubReq{Req: req, ID: reqID, Channel: sc}
	select {
	case session.PublishRequests <- pubreq:
	default:
		if s.srv.cfg.logger != nil {
			s.srv.cfg.logger.Warn("Too many publish reqs.")
		}
	}

	// per opcua spec, we don't respond now.  When data is available on the subscription,
	// the Subscription will respond in the background.
	return nil, nil
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.13.6
func (s *SubscriptionService) Republish(sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	if s.srv.cfg.logger != nil {
		s.srv.cfg.logger.Debug("Handling %T", r)
	}

	req, err := safeReq[*ua.RepublishRequest](r)
	if err != nil {
		return nil, err
	}

	session := s.srv.Session(req.RequestHeader)
	if session == nil {
		return nil, ua.StatusBadSessionIDInvalid
	}

	s.Mu.Lock()
	sub, ok := s.Subs[req.SubscriptionID]
	s.Mu.Unlock()
	if !ok || !sub.ownedBy(session) {
		// Part 4, Table 90: the subscription does not exist or does not belong
		// to the session making the request.
		return nil, ua.StatusBadSubscriptionIDInvalid
	}

	// Part 4, 5.13.6.2: the retained message is returned unchanged and the
	// retransmission does not remove it from the retransmission queue; only
	// an acknowledgement does that.
	msg, ok := sub.retainedMessage(req.RetransmitSequenceNumber)
	if !ok {
		// the message was acknowledged, discarded or never sent
		return nil, ua.StatusBadMessageNotAvailable
	}

	resp := &ua.RepublishResponse{
		ResponseHeader:      responseHeader(req.RequestHeader.RequestHandle, ua.StatusOK),
		NotificationMessage: msg,
	}
	return resp, nil
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.13.7
func (s *SubscriptionService) TransferSubscriptions(sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	if s.srv.cfg.logger != nil {
		s.srv.cfg.logger.Debug("Handling %T", r)
	}

	req, err := safeReq[*ua.TransferSubscriptionsRequest](r)
	if err != nil {
		return nil, err
	}

	session := s.srv.Session(req.RequestHeader)
	if session == nil {
		// Bad session token (e.g. the session was closed): the whole request
		// fails and no subscription is modified (Part 4, 5.13.7.3).
		return nil, ua.StatusBadSessionIDInvalid
	}

	if len(req.SubscriptionIDs) == 0 {
		return nil, ua.StatusBadNothingToDo
	}

	results := make([]*ua.TransferResult, len(req.SubscriptionIDs))

	// transferred collects the subscriptions which actually changed owner and
	// for which initial values have to be pushed when SendInitialValues is set.
	var transferred []*Subscription

	s.Mu.Lock()
	for i, subID := range req.SubscriptionIDs {
		sub, ok := s.Subs[subID]
		if !ok {
			results[i] = &ua.TransferResult{
				StatusCode:               ua.StatusBadSubscriptionIDInvalid,
				AvailableSequenceNumbers: []uint32{},
			}
			continue
		}
		if sub.ownedBy(session) {
			results[i] = &ua.TransferResult{
				StatusCode:               ua.StatusBadNothingToDo,
				AvailableSequenceNumbers: []uint32{},
			}
			continue
		}

		// Part 4, 5.13.7.2: report the sequence numbers still held in the
		// retransmission queue at the time of the transfer.
		results[i] = &ua.TransferResult{
			StatusCode:               ua.StatusOK,
			AvailableSequenceNumbers: sub.availableSequenceNumbers(),
		}
		sub.setOwner(session, sc)
		sub.signalOwner()
		transferred = append(transferred, sub)
	}
	s.Mu.Unlock()

	// Part 4, 5.13.7.2: with SendInitialValues the first notification the
	// transferred subscriptions publish to the new session contains the
	// current value of every monitored item.
	if req.SendInitialValues {
		for _, sub := range transferred {
			for _, nodeID := range s.srv.MonitoredItemService.nodesForSub(sub.ID) {
				// ChangeNotification takes the monitored item service lock, so
				// run it outside of the subscription service lock and, like
				// CreateMonitoredItems, in the background.
				nodeID := nodeID
				go s.srv.MonitoredItemService.ChangeNotification(nodeID)
			}
		}
	}

	resp := &ua.TransferSubscriptionsResponse{
		ResponseHeader:  responseHeader(req.RequestHeader.RequestHandle, ua.StatusOK),
		Results:         results,
		DiagnosticInfos: []*ua.DiagnosticInfo{},
	}
	return resp, nil
}

// https://reference.opcfoundation.org/Core/Part4/v105/docs/5.13.8
func (s *SubscriptionService) DeleteSubscriptions(sc *uasc.SecureChannel, r ua.Request, reqID uint32) (ua.Response, error) {
	if s.srv.cfg.logger != nil {
		s.srv.cfg.logger.Debug("Handling %T", r)
	}

	req, err := safeReq[*ua.DeleteSubscriptionsRequest](r)
	if err != nil {
		return nil, err
	}
	session := s.srv.Session(req.Header())

	s.Mu.Lock()
	defer s.Mu.Unlock()

	results := make([]ua.StatusCode, len(req.SubscriptionIDs))
	for i := range req.SubscriptionIDs {

		subid := req.SubscriptionIDs[i]
		if s.srv.cfg.logger != nil {
			s.srv.cfg.logger.Info("Subscription %d deleted by client", subid)
		}
		sub, ok := s.Subs[subid]
		if !ok {
			results[i] = ua.StatusBadSubscriptionIDInvalid
			continue
		}
		if !sub.ownedBy(session) {
			results[i] = ua.StatusBadSessionIDInvalid
			continue
		}
		// delete subscription gets the lock so we set them up to run in the background
		// once this function releases its lock
		go s.DeleteSubscription(subid)
		results[i] = ua.StatusOK
	}
	return &ua.DeleteSubscriptionsResponse{
		ResponseHeader: &ua.ResponseHeader{
			Timestamp:          time.Now(),
			RequestHandle:      req.RequestHeader.RequestHandle,
			ServiceResult:      ua.StatusOK,
			ServiceDiagnostics: &ua.DiagnosticInfo{},
			StringTable:        []string{},
			AdditionalHeader:   ua.NewExtensionObject(nil),
		},
		Results:         results,                //                  []StatusCode
		DiagnosticInfos: []*ua.DiagnosticInfo{}, //          []*DiagnosticInfo
	}, nil
}

type PubReq struct {
	// The data of the publish request
	Req *ua.PublishRequest

	// The request ID (from the header) of the publish request.  This has to be used when replying.
	ID uint32

	// Channel the request arrived on. The response must be sent on this
	// channel even if the subscription has been transferred to another
	// session (or detached) between request and response.
	Channel *uasc.SecureChannel
}

// This is the type that with its run() function will work in the bakground fullfilling subscription
// publishes.
//
// MonitoredItems will send updates on the NotifyChannel to let the background task know that
// an event has occured that needs to be published.
type Subscription struct {
	srv                       *SubscriptionService
	ID                        uint32
	RevisedPublishingInterval float64
	RevisedLifetimeCount      uint32
	RevisedMaxKeepAliveCount  uint32
	SequenceID                uint32
	T                         *time.Ticker

	NotifyChannel chan *ua.MonitoredItemNotification
	ModifyChannel chan *ua.ModifySubscriptionRequest

	// Session and Channel are the current owner of the subscription. They are
	// guarded by Mu: a subscription can be detached on CloseSession and
	// transferred to another session by TransferSubscriptions while the
	// background loop is running.
	Session *session
	Channel *uasc.SecureChannel

	// ownerCh is signaled (non-blocking, capacity 1) whenever Session/Channel
	// change so the background loop can re-select the owner's publish queue.
	ownerCh chan struct{}

	// retained is the retransmission queue of sent but unacknowledged data
	// notification messages, keyed by sequence number, with retainedSeqs
	// holding the sequence numbers in send order. Guarded by Mu.
	retained     map[uint32]*ua.NotificationMessage
	retainedSeqs []uint32

	// the running flag and shutdown channel are used to signal the background task that it should stop.
	// multiple places can kill the subscription so make sure you check the running flag using the mutex
	// before closing the shutdown channel.
	Mu       sync.Mutex
	running  bool
	shutdown chan struct{}
}

func NewSubscription() *Subscription {
	return &Subscription{
		NotifyChannel: make(chan *ua.MonitoredItemNotification, 100),
		ModifyChannel: make(chan *ua.ModifySubscriptionRequest, 2),
		ownerCh:       make(chan struct{}, 1),
		retained:      make(map[uint32]*ua.NotificationMessage),
		shutdown:      make(chan struct{}),
	}
}

func (s *Subscription) Update(req *ua.ModifySubscriptionRequest) {
	s.RevisedPublishingInterval = req.RequestedPublishingInterval
	s.RevisedLifetimeCount = req.RequestedLifetimeCount
	s.RevisedMaxKeepAliveCount = req.RequestedMaxKeepAliveCount
}

func (s *Subscription) Start() {
	go s.run()

}

// owner returns the session and channel currently owning the subscription.
// Either (and both) can be nil while the subscription is detached and waits
// for a TransferSubscriptions request.
func (s *Subscription) owner() (*session, *uasc.SecureChannel) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	return s.Session, s.Channel
}

// setOwner changes the session/channel owning the subscription.
func (s *Subscription) setOwner(sess *session, ch *uasc.SecureChannel) {
	s.Mu.Lock()
	s.Session = sess
	s.Channel = ch
	s.Mu.Unlock()
}

// signalOwner wakes the background loop so it re-reads the owner. A pending,
// unconsumed signal is enough, hence the non-blocking send.
func (s *Subscription) signalOwner() {
	select {
	case s.ownerCh <- struct{}{}:
	default:
	}
}

// ownedBy reports whether sess is the current owner of the subscription.
func (s *Subscription) ownedBy(sess *session) bool {
	if sess == nil {
		return false
	}
	own, _ := s.owner()
	return own != nil && own.AuthTokenID.String() == sess.AuthTokenID.String()
}

// allocateSequenceNumber returns the next publish sequence number. Zero is
// skipped, per the spec, and the numbers wrap at 2^32.
func (s *Subscription) allocateSequenceNumber() uint32 {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	s.SequenceID++
	if s.SequenceID == 0 {
		s.SequenceID = 1
	}
	return s.SequenceID
}

// keepaliveSequenceNumber returns the sequence number the next data
// notification would use, which is what keep-alive messages carry.
func (s *Subscription) keepaliveSequenceNumber() uint32 {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	next := s.SequenceID + 1
	if next == 0 {
		next = 1
	}
	return next
}

// retainMessage stores a sent data notification message for retransmission.
// When more than maxRetainedNotifications unacknowledged messages are queued
// the one with the smallest sequence number is discarded.
func (s *Subscription) retainMessage(msg *ua.NotificationMessage) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	if _, ok := s.retained[msg.SequenceNumber]; !ok {
		s.retainedSeqs = append(s.retainedSeqs, msg.SequenceNumber)
	}
	s.retained[msg.SequenceNumber] = msg
	for len(s.retainedSeqs) > maxRetainedNotifications {
		oldest := s.retainedSeqs[0]
		s.retainedSeqs = s.retainedSeqs[1:]
		delete(s.retained, oldest)
	}
}

// ackMessage removes a previously sent notification message from the
// retransmission queue. It returns Good when the message was still held and
// BadSequenceNumberUnknown otherwise.
func (s *Subscription) ackMessage(seq uint32) ua.StatusCode {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	if _, ok := s.retained[seq]; !ok {
		return ua.StatusBadSequenceNumberUnknown
	}
	delete(s.retained, seq)
	for i, v := range s.retainedSeqs {
		if v == seq {
			s.retainedSeqs = append(s.retainedSeqs[:i], s.retainedSeqs[i+1:]...)
			break
		}
	}
	return ua.StatusOK
}

// availableSequenceNumbers returns a snapshot of the sequence numbers held in
// the retransmission queue, in ascending order.
func (s *Subscription) availableSequenceNumbers() []uint32 {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	out := make([]uint32, 0, len(s.retainedSeqs))
	return append(out, s.retainedSeqs...)
}

// retainedMessage returns the stored message for a sequence number without
// removing it. Used by Republish.
func (s *Subscription) retainedMessage(seq uint32) (*ua.NotificationMessage, bool) {
	s.Mu.Lock()
	defer s.Mu.Unlock()
	msg, ok := s.retained[seq]
	return msg, ok
}

// responseChannel picks the channel the request that is being answered came
// in on, falling back to the owner channel for callers which did not record
// it.
func (p PubReq) responseChannel(fallback *uasc.SecureChannel) *uasc.SecureChannel {
	if p.Channel != nil {
		return p.Channel
	}
	return fallback
}

// buildKeepaliveResponse assembles the Publish response for a publishing
// interval without new data. Like the data response it processes the client
// acknowledgements and lists the notification messages still held for
// retransmission.
func (s *Subscription) buildKeepaliveResponse(pubreq PubReq) *ua.PublishResponse {
	results := s.srv.processAcknowledgements(pubreq.Req.SubscriptionAcknowledgements)
	available := s.availableSequenceNumbers()

	msg := &ua.NotificationMessage{
		SequenceNumber:   s.keepaliveSequenceNumber(), // the next sequence number to be used for a data notification
		PublishTime:      time.Now(),
		NotificationData: []*ua.ExtensionObject{},
	}

	return &ua.PublishResponse{
		ResponseHeader: &ua.ResponseHeader{
			Timestamp:          time.Now(),
			RequestHandle:      pubreq.Req.RequestHeader.RequestHandle,
			ServiceResult:      ua.StatusOK,
			ServiceDiagnostics: &ua.DiagnosticInfo{},
			StringTable:        []string{},
			AdditionalHeader:   ua.NewExtensionObject(nil),
		},
		SubscriptionID:           s.ID,
		MoreNotifications:        false,
		NotificationMessage:      msg,
		AvailableSequenceNumbers: available,
		Results:                  results,
		DiagnosticInfos:          []*ua.DiagnosticInfo{},
	}
}

// buildDataResponse assembles the Publish response carrying one data
// notification message. It processes the client acknowledgements, allocates
// the sequence number, stores the message in the retransmission queue (until
// acknowledged) and reports the resulting available sequence numbers.
func (s *Subscription) buildDataResponse(pubreq PubReq, items []*ua.MonitoredItemNotification) *ua.PublishResponse {
	seq := s.allocateSequenceNumber()
	results := s.srv.processAcknowledgements(pubreq.Req.SubscriptionAcknowledgements)

	dcn := ua.DataChangeNotification{
		MonitoredItems:  items,
		DiagnosticInfos: []*ua.DiagnosticInfo{},
	}
	eo := make([]*ua.ExtensionObject, 1)
	eo[0] = ua.NewExtensionObject(&dcn)
	eo[0].UpdateMask()

	msg := &ua.NotificationMessage{
		SequenceNumber:   seq,
		PublishTime:      time.Now(),
		NotificationData: eo,
	}

	// keep the message in the retransmission queue until acknowledged so
	// that Republish can hand it out unchanged
	s.retainMessage(msg)

	return &ua.PublishResponse{
		ResponseHeader: &ua.ResponseHeader{
			Timestamp:          time.Now(),
			RequestHandle:      pubreq.Req.RequestHeader.RequestHandle,
			ServiceResult:      ua.StatusOK,
			ServiceDiagnostics: &ua.DiagnosticInfo{},
			StringTable:        []string{},
			AdditionalHeader:   ua.NewExtensionObject(nil),
		},
		SubscriptionID:           s.ID,
		MoreNotifications:        false,
		NotificationMessage:      msg,
		AvailableSequenceNumbers: s.availableSequenceNumbers(),
		Results:                  results,
		DiagnosticInfos:          []*ua.DiagnosticInfo{},
	}
}

func (s *Subscription) sendResponse(pubreq PubReq, response *ua.PublishResponse) error {
	_, ch := s.owner()
	return pubreq.responseChannel(ch).SendResponseWithContext(context.Background(), pubreq.ID, response)
}

func (s *Subscription) keepalive(pubreq PubReq) error {
	return s.sendResponse(pubreq, s.buildKeepaliveResponse(pubreq))
}

// this function should be run as a go-routine and will handle sending data out
// to the client at the correct rate assuming there are publish requests queued up.
// if the function returns it deletes the subscription
func (s *Subscription) run() {
	// if this go routine dies, we need to delete ourselves.
	defer func() {
		if s.srv.srv.cfg.logger != nil {
			s.srv.srv.cfg.logger.Info("Subscription %d shutting down.", s.ID)
		}
		s.srv.DeleteSubscription(s.ID)
	}()

	keepalive_counter := 0
	lifetime_counter := 0
	//TODO: if a sub is modified, this ticker time may need to change.
	s.T = time.NewTicker(time.Millisecond * time.Duration(s.RevisedPublishingInterval))
	defer s.T.Stop()

	// This is the master run event loop.  It has effectively 3 states that it can be in.  The first two are designated with
	// the labels L0, and L2.  Everything after the L2 loop is the third state where we send any pending notifications.
	// The states always go L0 -> L2 -> Sending -> L0.  L0 and L2 are both places where we wait so they are done as for loops with
	// breaks to go to the next state.
	// The sending state always runs to completion.
	//
	// L0 waits for our notification interval to expire.  Any notifications that come in
	// while waiting will be stored in the publishQueue.  Once the interval expires, we'll move on to L2 if we've got notifications.
	// In L2 we wait for a publish request.  If we get one, we'll publish the notifications in the publishQueue.  If we don't
	// get a publish request, we'll continue to count intervals without a publish request.
	//
	// In L0 and L2, If we get to the lifetime count without a publish request, we'll kill the subscription.
	for {
		// we don't need to do anything if we don't have at least one thing to publish so lets get that first
		publishQueue := make(map[uint32]*ua.MonitoredItemNotification)

		// Collect notifications until our publication interval is ready
	L0:
		for {
			select {
			case <-s.shutdown:
				return
			case <-s.ownerCh:
				// owner changed (detach/transfer): re-read it on the next iteration
			case newNotification := <-s.NotifyChannel:
				publishQueue[newNotification.ClientHandle] = newNotification
			case <-s.T.C:
				own, _ := s.owner()
				if len(publishQueue) == 0 {
					// A detached subscription (session closed with
					// DeleteSubscriptions=false) keeps its notifications and
					// waits for a new owner; it neither sends keep-alives nor
					// expires.
					if own == nil {
						continue
					}
					// nothing to publish, increment the keepalive counter and send a keepalive if it
					// has been enough intervals.
					keepalive_counter++
					if keepalive_counter > int(s.RevisedMaxKeepAliveCount) {
						keepalive_counter = 0
						select {
						case pubreq := <-own.PublishRequests:
							err := s.keepalive(pubreq)
							if err != nil {
								if s.srv.srv.cfg.logger != nil {
									s.srv.srv.cfg.logger.Warn("problem sending keepalive to subscription #%d: %v", s.ID, err)
								}
								// The request may have come from a session/channel
								// the subscription no longer belongs to. The
								// subscription itself stays alive and waits for
								// the next publish request.
							}
						case <-s.ownerCh:
							// owner changed before we could answer; loop and
							// re-select the publish queue
						default:
							lifetime_counter++
							if lifetime_counter > int(s.RevisedLifetimeCount) {
								if s.srv.srv.cfg.logger != nil {
									s.srv.srv.cfg.logger.Warn("Subscription #%d timed out.", s.ID)
								}
								return
							}
						}
					}
					continue // nothing to publish this interval
				}
				// we have things to publish so we'll break out to do that.
				break L0
			case update := <-s.ModifyChannel:
				s.Update(update)
			}
		}
		var pubreq PubReq

		// now we need to continue to collect notifications until we've got a publish request
	L2:
		for {
			own, _ := s.owner()
			var publishRequests <-chan PubReq
			if own != nil {
				publishRequests = own.PublishRequests
			}
			select {
			case <-s.shutdown:
				return
			case <-s.ownerCh:
				// detached or transferred: reset the lifetime accounting and
				// loop to select the new owner's publish queue
				lifetime_counter = 0
				keepalive_counter = 0
				continue
			case pubreq = <-publishRequests:
				// once we get a publish request, we should move on to publish them back
				break L2
			case newNotification := <-s.NotifyChannel:
				publishQueue[newNotification.ClientHandle] = newNotification

			case <-s.T.C:
				own, _ := s.owner()
				if own == nil {
					// waiting to be transferred; do not expire
					continue
				}
				// we had another tick without a publish request.
				lifetime_counter++
				if lifetime_counter > int(s.RevisedLifetimeCount) {
					if s.srv.srv.cfg.logger != nil {
						s.srv.srv.cfg.logger.Warn("Subscription %d timed out.", s.ID)
					}
					return
				}
			}
		}
		lifetime_counter = 0
		keepalive_counter = 0

		if s.srv.srv.cfg.logger != nil {
			s.srv.srv.cfg.logger.Debug("Got publish req on sub #%d.", s.ID)
		}

		final_items := make([]*ua.MonitoredItemNotification, len(publishQueue))
		i := 0
		for k := range publishQueue {
			final_items[i] = publishQueue[k]
			i++
		}

		// process acknowledgements, allocate the sequence number, retain the
		// message for retransmission and report the available sequence numbers
		response := s.buildDataResponse(pubreq, final_items)

		err := s.sendResponse(pubreq, response)
		if err != nil {
			if s.srv.srv.cfg.logger != nil {
				s.srv.srv.cfg.logger.Error("problem sending channel response: %v", err)
			}
			// Do not kill the subscription: the request could have been
			// queued on a session the subscription has since been detached
			// from or transferred away from. The message stays in the
			// retransmission queue and can be republished; wait for the next
			// publish request.
		}
		if s.srv.srv.cfg.logger != nil {
			s.srv.srv.cfg.logger.Debug("Published %d items OK for %d", len(publishQueue), s.ID)
		}
		// wait till we've got a publish request.
	}
}

//PublishRequest_Encoding_DefaultBinary
