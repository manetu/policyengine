//
//  Copyright © Manetu Inc. All rights reserved.
//

package decisionpoint

import "context"

// Server is the interface for decision point servers that can be stopped gracefully.
type Server interface {
	Stop(context.Context) error
}
