//
//  Copyright © Manetu Inc. All rights reserved.
//

package accesslog

import (
	events "github.com/manetu/policyengine/pkg/protos/manetu/policyengine/events/v1"
)

// Factory is the interface for instantiating a new stream. The factory idiom is used, in part, to allow for
// a distinction between early and late initialization of the service.  Early init should be performed by
// the factory itself, such as installing Viper defaults, while late init should be performed when the NewStream
// method is called.  The framework will ensure that the configuration is loaded before calling NewStream.
type Factory interface {
	NewStream() (Stream, error)
}

// Stream defines the accesslog interface to send access records, such as stdout or kafka
type Stream interface {
	Send(record *events.AccessRecord) error
	Close()
}
