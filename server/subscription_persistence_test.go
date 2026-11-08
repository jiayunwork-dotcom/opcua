package server

import (
	"testing"
	"time"

	"github.com/gopcua/opcua/ua"
	"github.com/gopcua/opcua/uasc"
	"github.com/stretchr/testify/require"
)

// newSubscriptionTestServer builds a Server with its subscription and
// monitored item services wired up, without starting the network stack.
// Service handlers can then be driven directly, like the other in-package
// service tests do.
func newSubscriptionTestServer(t *testing.T) (*Server, *SubscriptionService, *MonitoredItemService) {
	t.Helper()

	srv := New()
	svc := &SubscriptionService{
		srv:  srv,
		Subs: make(map[uint32]*Subscription),
	}
	items := &MonitoredItemService{
		SubService: svc,
		Items:      make(map[uint32]*MonitoredItem),
		Nodes:      make(map[string][]*MonitoredItem),
		Subs:       make(map[uint32][]*MonitoredItem),
	}
	srv.SubscriptionService = svc
	srv.MonitoredItemService = items
	return srv, svc, items
}

func newIdleSub(svc *SubscriptionService, id uint32, sess *session) *Subscription {
	sub := NewSubscription()
	sub.srv = svc
	sub.ID = id
	sub.setOwner(sess, &uasc.SecureChannel{})
	svc.Subs[id] = sub
	return sub
}

// startTestSub starts the real background publishing loop of a subscription
// with a short publishing interval and a long lifetime/keep-alive so the
// test, not the counters, decides when it stops.
func startTestSub(t *testing.T, svc *SubscriptionService, id uint32, sess *session) *Subscription {
	t.Helper()

	sub := newIdleSub(svc, id, sess)
	sub.RevisedPublishingInterval = 10
	sub.RevisedLifetimeCount = 100000
	sub.RevisedMaxKeepAliveCount = 100000
	sub.Mu.Lock()
	sub.running = true
	sub.Mu.Unlock()
	sub.Start()
	t.Cleanup(func() { svc.DeleteSubscription(id) })
	return sub
}

func testPubReq(acks ...*ua.SubscriptionAcknowledgement) PubReq {
	return PubReq{
		Req: &ua.PublishRequest{
			RequestHeader:                &ua.RequestHeader{RequestHandle: 42},
			SubscriptionAcknowledgements: acks,
		},
		ID:      1,
		Channel: &uasc.SecureChannel{}, // zero channel: sends fail with an error instead of panicking
	}
}

func notify(handle uint32) *ua.MonitoredItemNotification {
	return &ua.MonitoredItemNotification{
		ClientHandle: handle,
		Value:        &ua.DataValue{},
	}
}

func addTestItem(items *MonitoredItemService, sub *Subscription, itemID, clientHandle uint32, nodeID *ua.NodeID) {
	item := &MonitoredItem{
		ID:  itemID,
		Sub: sub,
		Req: &ua.MonitoredItemCreateRequest{
			ItemToMonitor: &ua.ReadValueID{
				NodeID:      nodeID,
				AttributeID: ua.AttributeIDValue,
			},
			RequestedParameters: &ua.MonitoringParameters{ClientHandle: clientHandle},
		},
	}
	items.Items[itemID] = item
	items.Nodes[nodeID.String()] = append(items.Nodes[nodeID.String()], item)
	items.Subs[sub.ID] = append(items.Subs[sub.ID], item)
}

func requireEventually(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	require.Eventually(t, cond, 2*time.Second, 5*time.Millisecond, msg)
}

// TestRetainedQueueKeepsUnacknowledgedMessages checks the retransmission
// queue: retained sequence numbers are listed in order, acknowledgements
// remove exactly the named message and the 100 message limit discards the
// smallest sequence number first.
func TestRetainedQueueKeepsUnacknowledgedMessages(t *testing.T) {
	_, svc, _ := newSubscriptionTestServer(t)
	sub := newIdleSub(svc, 7, nil)

	msgFor := func(seq uint32) *ua.NotificationMessage {
		return &ua.NotificationMessage{
			SequenceNumber:   seq,
			NotificationData: []*ua.ExtensionObject{},
		}
	}

	for seq := uint32(1); seq <= 105; seq++ {
		sub.retainMessage(msgFor(seq))
	}

	// the five smallest sequence numbers had to make room
	require.Len(t, sub.availableSequenceNumbers(), 100)
	require.Equal(t, uint32(6), sub.availableSequenceNumbers()[0])
	require.Equal(t, uint32(105), sub.availableSequenceNumbers()[99])

	_, ok := sub.retainedMessage(1)
	require.False(t, ok, "seq 1 must have been discarded")
	_, ok = sub.retainedMessage(5)
	require.False(t, ok)
	_, ok = sub.retainedMessage(6)
	require.True(t, ok)
	_, ok = sub.retainedMessage(105)
	require.True(t, ok)

	// acknowledging a message removes it
	require.Equal(t, ua.StatusOK, sub.ackMessage(6))
	require.Equal(t, []uint32(seqRange(7, 105)), sub.availableSequenceNumbers())

	// a second acknowledgement of the same sequence is unknown now
	require.Equal(t, ua.StatusBadSequenceNumberUnknown, sub.ackMessage(6))
	// as is a sequence that never existed
	require.Equal(t, ua.StatusBadSequenceNumberUnknown, sub.ackMessage(4711))

	// retainedMessage is a read-only lookup used by Republish
	m, ok := sub.retainedMessage(105)
	require.True(t, ok)
	require.Equal(t, uint32(105), m.SequenceNumber)
	require.Equal(t, []uint32(seqRange(7, 105)), sub.availableSequenceNumbers(),
		"Republish lookup must not remove the message")
}

func seqRange(from, to uint32) []uint32 {
	out := make([]uint32, 0, to-from+1)
	for i := from; i <= to; i++ {
		out = append(out, i)
	}
	return out
}

// TestProcessAcknowledgements verifies the per-acknowledgement result codes
// and that an acknowledgement only affects the subscription it names.
func TestProcessAcknowledgements(t *testing.T) {
	_, svc, _ := newSubscriptionTestServer(t)
	sub1 := newIdleSub(svc, 1, nil)
	sub2 := newIdleSub(svc, 2, nil)

	sub1.retainMessage(&ua.NotificationMessage{SequenceNumber: 10})
	sub1.retainMessage(&ua.NotificationMessage{SequenceNumber: 11})
	sub2.retainMessage(&ua.NotificationMessage{SequenceNumber: 10})

	acks := []*ua.SubscriptionAcknowledgement{
		{SubscriptionID: 1, SequenceNumber: 10},  // known -> Good
		{SubscriptionID: 1, SequenceNumber: 99},  // unknown seq
		{SubscriptionID: 2, SequenceNumber: 10},  // other sub, known -> Good
		{SubscriptionID: 999, SequenceNumber: 1}, // unknown subscription
		nil,                                      // malformed
	}

	results := svc.processAcknowledgements(acks)
	require.Equal(t, []ua.StatusCode{
		ua.StatusOK,
		ua.StatusBadSequenceNumberUnknown,
		ua.StatusOK,
		ua.StatusBadSubscriptionIDInvalid,
		ua.StatusBadSequenceNumberUnknown,
	}, results)

	require.Equal(t, []uint32{11}, sub1.availableSequenceNumbers())
	// sub 2's message 10 is unrelated to the sub 1 acknowledgements and was
	// removed by its own acknowledgement
	require.Empty(t, sub2.availableSequenceNumbers())
}

// TestKeepaliveResponseListsRetainedAndAcknowledges checks that even a
// keep-alive Publish response reports the retransmission queue and the
// acknowledgement results, and carries the next sequence number without
// adding a retained message.
func TestKeepaliveResponseListsRetainedAndAcknowledges(t *testing.T) {
	_, svc, _ := newSubscriptionTestServer(t)
	sub := newIdleSub(svc, 3, nil)

	sub.Mu.Lock()
	sub.SequenceID = 2
	sub.Mu.Unlock()
	sub.retainMessage(&ua.NotificationMessage{SequenceNumber: 1})
	sub.retainMessage(&ua.NotificationMessage{SequenceNumber: 2})

	pubreq := testPubReq(
		&ua.SubscriptionAcknowledgement{SubscriptionID: 3, SequenceNumber: 1},
		&ua.SubscriptionAcknowledgement{SubscriptionID: 3, SequenceNumber: 99},
		&ua.SubscriptionAcknowledgement{SubscriptionID: 444, SequenceNumber: 1},
	)

	resp := sub.buildKeepaliveResponse(pubreq)
	require.Equal(t, ua.StatusOK, resp.ResponseHeader.ServiceResult)
	require.Equal(t, uint32(3), resp.SubscriptionID)
	require.Empty(t, resp.NotificationMessage.NotificationData, "keep-alive carries no data")
	require.Equal(t, uint32(3), resp.NotificationMessage.SequenceNumber, "next data sequence number")
	require.Equal(t, []uint32{2}, resp.AvailableSequenceNumbers)
	require.Equal(t, []ua.StatusCode{
		ua.StatusOK,
		ua.StatusBadSequenceNumberUnknown,
		ua.StatusBadSubscriptionIDInvalid,
	}, resp.Results)
}

// TestDataResponseRetainsAndLists checks the data-carrying Publish response:
// the sent message is retained until acknowledged, and AvailableSequenceNumbers
// always reflects the queue after processing the request's acknowledgements.
func TestDataResponseRetainsAndLists(t *testing.T) {
	_, svc, _ := newSubscriptionTestServer(t)
	sub := newIdleSub(svc, 5, nil)

	// first notification: seq 1, no acks yet
	resp1 := sub.buildDataResponse(testPubReq(), []*ua.MonitoredItemNotification{notify(100)})
	require.Equal(t, uint32(1), resp1.NotificationMessage.SequenceNumber)
	require.Equal(t, []uint32{1}, resp1.AvailableSequenceNumbers)
	require.Empty(t, resp1.Results)
	require.Len(t, resp1.NotificationMessage.NotificationData, 1)

	// second notification acknowledges seq 1
	pubreq := testPubReq(&ua.SubscriptionAcknowledgement{SubscriptionID: 5, SequenceNumber: 1})
	resp2 := sub.buildDataResponse(pubreq, []*ua.MonitoredItemNotification{notify(100)})
	require.Equal(t, uint32(2), resp2.NotificationMessage.SequenceNumber)
	require.Equal(t, []ua.StatusCode{ua.StatusOK}, resp2.Results)
	require.Equal(t, []uint32{2}, resp2.AvailableSequenceNumbers, "seq 1 was acknowledged and removed")

	// the retained content matches what was sent first
	m, ok := sub.retainedMessage(2)
	require.True(t, ok)
	require.Equal(t, resp2.NotificationMessage, m)
}

// TestRepublishService covers Part 4 5.13.6: the retained message is returned
// unchanged and is not removed by retransmission, with the required status
// codes for unknown subscriptions, other sessions and missing sequences.
func TestRepublishService(t *testing.T) {
	srv, svc, _ := newSubscriptionTestServer(t)
	sessA := srv.sb.NewSession()
	sessB := srv.sb.NewSession()

	sub := newIdleSub(svc, 11, sessA)
	sub.retainMessage(&ua.NotificationMessage{
		SequenceNumber:   1,
		NotificationData: []*ua.ExtensionObject{},
	})
	sub.SequenceID = 1

	republishReq := func(sess *session, subID, seq uint32) *ua.RepublishRequest {
		token := (*ua.NodeID)(nil)
		if sess != nil {
			token = sess.AuthTokenID
		}
		return &ua.RepublishRequest{
			RequestHeader:            &ua.RequestHeader{AuthenticationToken: token},
			SubscriptionID:           subID,
			RetransmitSequenceNumber: seq,
		}
	}

	// unknown session token
	_, err := svc.Republish(nil, republishReq(nil, 11, 1), 0)
	require.Equal(t, ua.StatusBadSessionIDInvalid, err)

	// unknown subscription
	_, err = svc.Republish(nil, republishReq(sessA, 12, 1), 0)
	require.Equal(t, ua.StatusBadSubscriptionIDInvalid, err)

	// subscription owned by another session
	_, err = svc.Republish(nil, republishReq(sessB, 11, 1), 0)
	require.Equal(t, ua.StatusBadSubscriptionIDInvalid, err)

	// sequence acknowledged/discarded/never sent
	_, err = svc.Republish(nil, republishReq(sessA, 11, 2), 0)
	require.Equal(t, ua.StatusBadMessageNotAvailable, err)

	// happy path
	resp, err := svc.Republish(nil, republishReq(sessA, 11, 1), 0)
	require.NoError(t, err)
	rp, ok := resp.(*ua.RepublishResponse)
	require.True(t, ok)
	require.Equal(t, ua.StatusOK, rp.ResponseHeader.ServiceResult)
	require.Equal(t, uint32(1), rp.NotificationMessage.SequenceNumber)

	// the retransmitted message is the same message and is still retained
	m, ok := sub.retainedMessage(1)
	require.True(t, ok)
	require.Equal(t, m, rp.NotificationMessage)
	require.Equal(t, []uint32{1}, sub.availableSequenceNumbers(),
		"retransmission must not remove the message")

	// once acknowledged it is gone and Republish reports BadMessageNotAvailable
	require.Equal(t, ua.StatusOK, sub.ackMessage(1))
	_, err = svc.Republish(nil, republishReq(sessA, 11, 1), 0)
	require.Equal(t, ua.StatusBadMessageNotAvailable, err)
}

// TestTransferSubscriptionsService covers Part 4 5.13.7 result codes,
// queue reporting and ownership change.
func TestTransferSubscriptionsService(t *testing.T) {
	srv, svc, items := newSubscriptionTestServer(t)
	sessA := srv.sb.NewSession()
	sessB := srv.sb.NewSession()

	subA := newIdleSub(svc, 21, sessA)
	subA.retainMessage(&ua.NotificationMessage{SequenceNumber: 1})
	subA.retainMessage(&ua.NotificationMessage{SequenceNumber: 2})
	subOwn := newIdleSub(svc, 22, sessB)

	transferReq := func(sess *session, ids []uint32, initial bool) *ua.TransferSubscriptionsRequest {
		return &ua.TransferSubscriptionsRequest{
			RequestHeader:     &ua.RequestHeader{AuthenticationToken: sess.AuthTokenID},
			SubscriptionIDs:   ids,
			SendInitialValues: initial,
		}
	}

	// an unknown session token fails the whole request and changes nothing
	_, err := svc.TransferSubscriptions(nil, &ua.TransferSubscriptionsRequest{
		RequestHeader:   &ua.RequestHeader{AuthenticationToken: ua.NewNumericNodeID(0, 999999)},
		SubscriptionIDs: []uint32{21},
	}, 0)
	require.Equal(t, ua.StatusBadSessionIDInvalid, err)
	require.True(t, subA.ownedBy(sessA), "bad session must not move any subscription")

	// an empty id list fails the whole request with BadNothingToDo
	_, err = svc.TransferSubscriptions(nil, transferReq(sessB, nil, false), 0)
	require.Equal(t, ua.StatusBadNothingToDo, err)

	// mixed: unknown id, already owned, successful transfer, repeated id
	resp, err := svc.TransferSubscriptions(nil, transferReq(sessB, []uint32{999, 22, 21, 21}, false), 0)
	require.NoError(t, err)
	tr, ok := resp.(*ua.TransferSubscriptionsResponse)
	require.True(t, ok)
	require.Len(t, tr.Results, 4)
	require.Equal(t, ua.StatusBadSubscriptionIDInvalid, tr.Results[0].StatusCode)
	require.Equal(t, ua.StatusBadNothingToDo, tr.Results[1].StatusCode)
	require.Equal(t, ua.StatusOK, tr.Results[2].StatusCode)
	require.Equal(t, []uint32{1, 2}, tr.Results[2].AvailableSequenceNumbers)
	require.Equal(t, ua.StatusBadNothingToDo, tr.Results[3].StatusCode, "duplicate id is already owned after the first transfer")

	require.True(t, subA.ownedBy(sessB))
	require.True(t, subOwn.ownedBy(sessB))
	require.Equal(t, []uint32{1, 2}, subA.availableSequenceNumbers(), "retained messages survive the transfer")

	// transferring an orphaned (detached) subscription works
	subA.setOwner(nil, nil)
	resp, err = svc.TransferSubscriptions(nil, transferReq(sessA, []uint32{21}, false), 0)
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, resp.(*ua.TransferSubscriptionsResponse).Results[0].StatusCode)
	require.True(t, subA.ownedBy(sessA))

	// SendInitialValues pushes the current value of every monitored item
	nodeID := ua.NewNumericNodeID(0, 2258) // CurrentTime node of the built-in ns=0 node set
	addTestItem(items, subA, 1001, 9001, nodeID)
	// drain anything queued while attaching the item
	for len(subA.NotifyChannel) > 0 {
		<-subA.NotifyChannel
	}
	resp, err = svc.TransferSubscriptions(nil, transferReq(sessB, []uint32{21}, true), 0)
	require.NoError(t, err)
	require.Equal(t, ua.StatusOK, resp.(*ua.TransferSubscriptionsResponse).Results[0].StatusCode)
	requireEventually(t, func() bool { return len(subA.NotifyChannel) > 0 },
		"SendInitialValues must enqueue current values")
	notif := <-subA.NotifyChannel
	require.Equal(t, uint32(9001), notif.ClientHandle)
	require.NotNil(t, notif.Value)

	// SendInitialValues=false does not trigger an extra push
	subA.setOwner(nil, nil)
	for len(subA.NotifyChannel) > 0 {
		<-subA.NotifyChannel
	}
	_, err = svc.TransferSubscriptions(nil, transferReq(sessA, []uint32{21}, false), 0)
	require.NoError(t, err)
	time.Sleep(100 * time.Millisecond)
	require.Empty(t, subA.NotifyChannel)
}

// TestCloseSessionDeleteSubscriptionsTrue verifies that closing a session
// with DeleteSubscriptions removes that session's subscriptions and monitored
// items while another session keeps everything.
func TestCloseSessionDeleteSubscriptionsTrue(t *testing.T) {
	srv, svc, items := newSubscriptionTestServer(t)
	ss := &SessionService{srv: srv}
	sessA := srv.sb.NewSession()
	sessB := srv.sb.NewSession()

	subA := newIdleSub(svc, 31, sessA)
	subB := newIdleSub(svc, 32, sessB)
	nodeA := ua.NewStringNodeID(2, "a")
	nodeB := ua.NewStringNodeID(2, "b")
	addTestItem(items, subA, 2001, 1, nodeA)
	addTestItem(items, subB, 2002, 2, nodeB)

	closeReq := &ua.CloseSessionRequest{
		RequestHeader:       &ua.RequestHeader{AuthenticationToken: sessA.AuthTokenID},
		DeleteSubscriptions: true,
	}
	resp, err := ss.CloseSession(nil, closeReq, 0)
	require.NoError(t, err)
	_, ok := resp.(*ua.CloseSessionResponse)
	require.True(t, ok)

	// A's subscription and items are gone, B's are untouched
	svc.Mu.Lock()
	_, aExists := svc.Subs[31]
	_, bExists := svc.Subs[32]
	svc.Mu.Unlock()
	require.False(t, aExists)
	require.True(t, bExists)

	items.Mu.Lock()
	_, aItemExists := items.Items[2001]
	_, bItemExists := items.Items[2002]
	_, aSubItems := items.Subs[31]
	_, bSubItems := items.Subs[32]
	items.Mu.Unlock()
	require.False(t, aItemExists)
	require.True(t, bItemExists)
	require.False(t, aSubItems)
	require.True(t, bSubItems)

	// the session itself is closed, B remains
	require.Nil(t, srv.sb.Session(sessA.AuthTokenID))
	require.NotNil(t, srv.sb.Session(sessB.AuthTokenID))

	// closing the same session again is rejected
	_, err = ss.CloseSession(nil, closeReq, 0)
	require.Equal(t, ua.StatusBadSessionIDInvalid, err)
}

// TestCloseSessionDeleteSubscriptionsFalse verifies that subscriptions and
// monitored items survive a session close, become detached and can be taken
// over by another session with TransferSubscriptions.
func TestCloseSessionDeleteSubscriptionsFalse(t *testing.T) {
	srv, svc, items := newSubscriptionTestServer(t)
	ss := &SessionService{srv: srv}
	sessA := srv.sb.NewSession()
	sessB := srv.sb.NewSession()

	subA := newIdleSub(svc, 41, sessA)
	subA.retainMessage(&ua.NotificationMessage{SequenceNumber: 1})
	subB := newIdleSub(svc, 42, sessB)
	nodeA := ua.NewStringNodeID(2, "a")
	nodeB := ua.NewStringNodeID(2, "b")
	addTestItem(items, subA, 3001, 1, nodeA)
	addTestItem(items, subB, 3002, 2, nodeB)

	closeReq := &ua.CloseSessionRequest{
		RequestHeader:       &ua.RequestHeader{AuthenticationToken: sessA.AuthTokenID},
		DeleteSubscriptions: false,
	}
	_, err := ss.CloseSession(nil, closeReq, 0)
	require.NoError(t, err)

	// both subscriptions and all monitored items survive
	svc.Mu.Lock()
	_, aExists := svc.Subs[41]
	_, bExists := svc.Subs[42]
	svc.Mu.Unlock()
	require.True(t, aExists)
	require.True(t, bExists)

	items.Mu.Lock()
	_, aItemExists := items.Items[3001]
	_, bItemExists := items.Items[3002]
	items.Mu.Unlock()
	require.True(t, aItemExists)
	require.True(t, bItemExists)

	// A's subscription is detached but retains its messages
	owner, _ := subA.owner()
	require.Nil(t, owner)
	require.Equal(t, []uint32{1}, subA.availableSequenceNumbers())
	require.True(t, subB.ownedBy(sessB), "B must not be touched")

	// B can take over A's subscription, with the retained sequence reported
	resp, err := svc.TransferSubscriptions(nil, &ua.TransferSubscriptionsRequest{
		RequestHeader:   &ua.RequestHeader{AuthenticationToken: sessB.AuthTokenID},
		SubscriptionIDs: []uint32{41, 42},
	}, 0)
	require.NoError(t, err)
	tr := resp.(*ua.TransferSubscriptionsResponse)
	require.Equal(t, ua.StatusOK, tr.Results[0].StatusCode)
	require.Equal(t, []uint32{1}, tr.Results[0].AvailableSequenceNumbers)
	require.Equal(t, ua.StatusBadNothingToDo, tr.Results[1].StatusCode)
	require.True(t, subA.ownedBy(sessB))
}

// TestPublishHandlerSessionAndQueue checks the immediate Publish handling:
// an unknown session gets BadSessionIdInvalid, a valid request is queued on
// the session together with the secure channel it arrived on.
func TestPublishHandlerSessionAndQueue(t *testing.T) {
	srv, svc, _ := newSubscriptionTestServer(t)
	sess := srv.sb.NewSession()
	ch := &uasc.SecureChannel{}

	unknown := &ua.PublishRequest{
		RequestHeader: &ua.RequestHeader{AuthenticationToken: ua.NewNumericNodeID(0, 424242)},
	}
	resp, err := svc.Publish(ch, unknown, 7)
	require.NoError(t, err)
	require.Equal(t, ua.StatusBadSessionIDInvalid, resp.(*ua.PublishResponse).ResponseHeader.ServiceResult)

	req := &ua.PublishRequest{
		RequestHeader:                &ua.RequestHeader{AuthenticationToken: sess.AuthTokenID},
		SubscriptionAcknowledgements: []*ua.SubscriptionAcknowledgement{},
	}
	resp, err = svc.Publish(ch, req, 9)
	require.NoError(t, err)
	require.Nil(t, resp, "Publish is answered asynchronously")
	require.Len(t, sess.PublishRequests, 1)
	queued := <-sess.PublishRequests
	require.Equal(t, uint32(9), queued.ID)
	require.Equal(t, ch, queued.Channel)
}

// TestRunLoopFollowsOwnership drives the real subscription goroutine without
// a network (the zero-value secure channel fails sends without panicking) and
// verifies that after a transfer notifications are consumed from the new
// session's publish queue, that a detached subscription stays alive and that
// shutting down removes it. Run with -race.
func TestRunLoopFollowsOwnership(t *testing.T) {
	_, svc, _ := newSubscriptionTestServer(t)
	sessA := svc.srv.sb.NewSession()
	sessB := svc.srv.sb.NewSession()

	sub := startTestSub(t, svc, 51, sessA)

	// a couple of spare publish requests on A cover a potential keep-alive
	// consuming one; data publication also takes one.
	for i := 0; i < 3; i++ {
		sessA.PublishRequests <- testPubReq()
	}
	sub.NotifyChannel <- notify(7001)

	requireEventually(t, func() bool {
		_, ok := sub.retainedMessage(1)
		return ok
	}, "first notification published on session A")

	// transfer to B before the next notification
	sub.setOwner(sessB, &uasc.SecureChannel{})
	sub.signalOwner()
	for i := 0; i < 3; i++ {
		sessB.PublishRequests <- testPubReq()
	}
	sub.NotifyChannel <- notify(7002)

	requireEventually(t, func() bool {
		_, ok := sub.retainedMessage(2)
		return ok
	}, "second notification published on session B")

	// B's queue was consumed (3 -> 2) while A's leftover requests are still
	// queued on A: the loop reads the new owner's queue after transfer.
	requireEventually(t, func() bool { return len(sessB.PublishRequests) == 2 }, "B queue consumed")
	require.Len(t, sessA.PublishRequests, 2, "A queue must not be consumed after transfer")

	// concurrent read access while the loop keeps running must be race free
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				sub.availableSequenceNumbers()
				_, _ = sub.retainedMessage(1)
			}
		}
	}()

	// detach: subscription must stay alive, keep collecting and neither
	// publish nor expire while waiting for a new owner
	sub.setOwner(nil, nil)
	sub.signalOwner()
	sub.NotifyChannel <- notify(7003)
	time.Sleep(80 * time.Millisecond)

	select {
	case <-sub.shutdown:
		t.Fatal("detached subscription must not shut down while waiting for transfer")
	default:
	}
	_, ok := sub.retainedMessage(3)
	require.False(t, ok, "no publish request, no new sequence number without an owner")
	close(stop)

	// explicit deletion shuts the loop down and removes the subscription
	svc.DeleteSubscription(51)
	requireEventually(t, func() bool {
		svc.Mu.Lock()
		_, exists := svc.Subs[51]
		svc.Mu.Unlock()
		return !exists
	}, "deleted subscription removed")
}
