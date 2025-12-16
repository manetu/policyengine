//
//  Copyright © Manetu Inc. All rights reserved.
//

package accesslog

import (
	"github.com/manetu/policyengine/pkg/core/accesslog"
	events "github.com/manetu/policyengine/pkg/protos/manetu/policyengine/events/v1"
)

// ChannelFactory factory for ChannelStream
type ChannelFactory struct {
	ch chan *events.AccessRecord
}

// ChannelStream implements the Stream interface by writing access records to a channel.
type ChannelStream struct {
	ch chan *events.AccessRecord
}

// NewChannelLogger creates a new Stream for logging access records to a channel.
func NewChannelLogger(ch chan *events.AccessRecord) accesslog.Factory {
	return &ChannelFactory{ch: ch}
}

// NewStream creates a new Stream to satisfy the Factory interface.
func (f *ChannelFactory) NewStream() (accesslog.Stream, error) {
	return &ChannelStream{ch: f.ch}, nil
}

// Send emulates the production of a kafka event by sending an access record to the channel.
func (s *ChannelStream) Send(m *events.AccessRecord) error {
	s.ch <- m

	return nil
}

// Close finalizes the access log by closing the underlying channel.
func (s *ChannelStream) Close() {
	if s.ch != nil {
		close(s.ch)
	}
}
