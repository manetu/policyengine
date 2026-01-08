//
//  Copyright © Manetu Inc. All rights reserved.
//

package core

import (
	events "github.com/manetu/policyengine/pkg/protos/manetu/policyengine/events/v1"
)

/* Every PolicyEngine::Authorize call evaluates the conjunction of policy evals over the identity
 * and resource (along with other context such as annotations) derived from the passed PORC. These
 * evaluations proceed in "phases". The phases are evaluated concurrently and the final evaluation
 * is the anded result from the individual phases
 */
type phase struct {
	bundles  []*events.AccessRecord_BundleReference
	duration uint64 // total phase duration in nanoseconds
}

func (p *phase) append(r *events.AccessRecord_BundleReference) {
	p.bundles = append(p.bundles, r)
}
