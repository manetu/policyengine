//
//  Copyright © Manetu Inc. All rights reserved.
//

package backend

import (
	"context"

	"github.com/manetu/policyengine/pkg/common"
	"github.com/manetu/policyengine/pkg/core/model"
	"github.com/manetu/policyengine/pkg/core/opa"
)

// Factory is the interface for instantiating a backend service. The factory idiom is used, in part, to allow for
// a distinction between early and late initialization of the backend service.  Early init should be performed by
// the factory itself, such as installing Viper defaults, while late init should be performed when the NewBackend
// method is called.  The framework will ensure that the configuration is loaded before calling NewBackend.
type Factory interface {
	NewBackend(*opa.Compiler) (Service, error)
}

// Service is the interface for policy engine backend services, such as retrieving policies or roles from a datastore.
type Service interface {
	GetRole(ctx context.Context, mrn string) (*model.PolicyReference, *common.PolicyError)
	GetGroup(ctx context.Context, mrn string) (*model.Group, *common.PolicyError)
	GetScope(ctx context.Context, mrn string) (*model.PolicyReference, *common.PolicyError)
	GetResource(ctx context.Context, mrn string) (*model.Resource, *common.PolicyError)
	GetResourceGroup(ctx context.Context, mrn string) (*model.PolicyReference, *common.PolicyError)
	GetOperation(ctx context.Context, mrn string) (*model.PolicyReference, *common.PolicyError)
}
