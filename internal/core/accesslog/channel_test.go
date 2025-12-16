//
//  Copyright © Manetu Inc. All rights reserved.
//

package accesslog

import (
	"testing"

	events "github.com/manetu/policyengine/pkg/protos/manetu/policyengine/events/v1"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestChannelInstantiate(t *testing.T) {
	ch := make(chan *events.AccessRecord, 10)
	stream := NewChannelLogger(ch)
	assert.NotNil(t, stream)
}

func TestChannelLoggerSend(t *testing.T) {
	ch := make(chan *events.AccessRecord, 10)
	logger := &ChannelStream{ch: ch}

	record := &events.AccessRecord{
		Operation: "test:operation",
		Resource:  "test:resource",
		Decision:  events.AccessRecord_GRANT,
		Metadata: &events.AccessRecord_Metadata{
			Id:        "test-id",
			Timestamp: timestamppb.Now(),
		},
	}

	err := logger.Send(record)
	assert.NoError(t, err)

	// Verify record was sent
	select {
	case received := <-ch:
		assert.Equal(t, "test:operation", received.Operation)
		assert.Equal(t, "test:resource", received.Resource)
		assert.Equal(t, events.AccessRecord_GRANT, received.Decision)
	default:
		t.Fatal("Expected record to be sent to channel")
	}
}

func TestChannelLoggerClose(t *testing.T) {
	ch := make(chan *events.AccessRecord, 10)
	logger := &ChannelStream{ch: ch}

	logger.Close()

	// Verify channel is closed
	_, ok := <-ch
	assert.False(t, ok, "Channel should be closed")
}

func TestChannelLoggerCloseWithNilChannel(t *testing.T) {
	logger := &ChannelStream{ch: nil}

	// Should not panic
	assert.NotPanics(t, func() {
		logger.Close()
	})
}
