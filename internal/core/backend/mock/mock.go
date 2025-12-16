//
//  Copyright © Manetu Inc. All rights reserved.
//

package mock

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/manetu/policyengine/internal/logging"
	"github.com/manetu/policyengine/pkg/common"
	"github.com/manetu/policyengine/pkg/core/backend"
	"github.com/manetu/policyengine/pkg/core/config"
	"github.com/manetu/policyengine/pkg/core/model"
	"github.com/manetu/policyengine/pkg/core/opa"
	events "github.com/manetu/policyengine/pkg/protos/manetu/policyengine/events/v1"
)

const (
	// mpe-config.yaml config names
	cfgMrn            = "mrn"
	cfgPolicyName     = "name"
	cfgPolicyFilename = "filename"
	cfgPolicy         = "policy"
	cfgSelector       = "selector"
	cfgRole           = "role"
	cfgMetadata       = "metadata"
	cfgGroup          = "group"
	cfgOwner          = "owner"
	cfgAnnotations    = "annotations"
	cfgClassification = "classification"

	mockDomainCfg string = "mock.domain"
)

var logger = logging.GetLogger("policyengine.backend.mock")
var mockAgent string = "mock"

// Factory ...
type Factory struct {
}

// Backend ...
type Backend struct {
	compiler       *opa.Compiler
	mapperCompiler *opa.Compiler
}

// NewFactory creates a new Factory for the mock backend.
func NewFactory() backend.Factory {
	return &Factory{}
}

// NewBackend creates a new mock Backend with the specified compiler.
func (f *Factory) NewBackend(compiler *opa.Compiler) (backend.Service, error) {
	logger.Warn(mockAgent, "Init", "RUNNING IN MOCK MODE. SHOULD NOT BE USED IN PRODUCTION")
	// Create a separate OPA compiler for mappers, since they don't want/need unsafe builtin exclusions like the policy compiler does
	mapperCompiler := compiler.Clone(opa.WithDefaultCapabilities())
	return &Backend{
		compiler:       compiler,
		mapperCompiler: mapperCompiler,
	}, nil
}

// getPolicy retrieves a policy by its MRN from the mock backend configuration.
func (b *Backend) getPolicy(ctx context.Context, mrn string) (*model.Policy, *common.PolicyError) {
	if strings.Contains(mrn, "networkerror") {
		return nil, &common.PolicyError{ReasonCode: events.AccessRecord_BundleReference_NETWORK_ERROR, Reason: "network error"}
	}

	policyConfig := config.VConfig.Get(fmt.Sprintf("%s.policies", mockDomainCfg))
	if policyConfig == nil {
		return nil, common.NewError(events.AccessRecord_BundleReference_NOTFOUND_ERROR, fmt.Sprintf("policy not found: %s", mrn))
	}

	for _, policy := range policyConfig.([]interface{}) {
		policyMap := policy.(map[string]interface{})
		_pmrn, ok := policyMap[cfgMrn]
		if !ok || mrn != _pmrn.(string) {
			continue
		}

		name, ok := policyMap[cfgPolicyName]
		if !ok {
			return nil, common.NewError(events.AccessRecord_BundleReference_NOTFOUND_ERROR, fmt.Sprintf("policy not found: %s", mrn))
		}
		filename, ok := policyMap[cfgPolicyFilename]
		if !ok {
			return nil, common.NewError(events.AccessRecord_BundleReference_NOTFOUND_ERROR, fmt.Sprintf("policy not found: %s", mrn))
		}

		doc := config.VConfig.GetString(fmt.Sprintf("%s.filedata.%s", mockDomainCfg, filename.(string)))
		if len(doc) == 0 {
			// data not in config so try to read from filesystem relative to the config yaml
			configfilename := config.VConfig.ConfigFileUsed()
			dir := filepath.Dir(configfilename)
			filedata, err := os.ReadFile(filepath.Clean(dir + string(filepath.Separator) + filename.(string)))
			if err == nil {
				doc = string(filedata)
			}
		}
		if len(doc) == 0 {
			return nil, common.NewError(events.AccessRecord_BundleReference_NOTFOUND_ERROR, fmt.Sprintf("policy not found: %s", mrn))
		}

		pm := map[string]string{}
		pm[name.(string)] = doc
		policy, err := b.compiler.Compile(mrn, pm)
		if err != nil {
			return nil, common.NewError(events.AccessRecord_BundleReference_COMPILATION_ERROR, fmt.Sprintf("compilation failed: %s", mrn))
		}

		h := sha256.New()
		h.Write([]byte(mrn))
		h.Write([]byte(doc))

		return &model.Policy{
			Mrn:         mrn,
			Fingerprint: h.Sum(nil), // doesn't really matter for mock, but we should return a realistic value
			Ast:         policy,
		}, nil
	}

	return nil, common.NewError(events.AccessRecord_BundleReference_NOTFOUND_ERROR, fmt.Sprintf("policy not found: %s", mrn))
}

func (b *Backend) generatePolicyReference(ctx context.Context, mrn, policyMrn string, annotations map[string]string) (*model.PolicyReference, *common.PolicyError) {
	policy, err := b.getPolicy(context.Background(), policyMrn)
	if err != nil {
		return nil, err
	}

	return &model.PolicyReference{
		Mrn:         mrn,
		Policy:      policy,
		Annotations: model.UnsafeToJSON(annotations),
	}, nil
}

// GetRole retrieves a role by its MRN from the mock backend configuration.
func (b *Backend) GetRole(ctx context.Context, mrn string) (*model.PolicyReference, *common.PolicyError) {
	if strings.Contains(mrn, "networkerror") {
		return nil, &common.PolicyError{ReasonCode: events.AccessRecord_BundleReference_NETWORK_ERROR, Reason: "network error"}
	}

	roleConfig := config.VConfig.Get(fmt.Sprintf("%s.roles", mockDomainCfg))
	if roleConfig == nil {
		return nil, common.NewError(events.AccessRecord_BundleReference_NOTFOUND_ERROR, fmt.Sprintf("role not found 1: %s", mrn))
	}
	logger.Debugf(mockAgent, "getRole", "read roleConfig: %+v", roleConfig.([]interface{}))

	for _, role := range roleConfig.([]interface{}) {
		roleMap := role.(map[string]interface{})
		logger.Debugf(mockAgent, "getRole", "roles: %+v", roleMap)

		_rmrn, ok := roleMap[cfgMrn]
		if !ok || mrn != _rmrn.(string) {
			logger.Debugf(mockAgent, "getRole", "mrn: %s not equal %s", _rmrn.(string), mrn)
			continue
		}

		policies, ok := roleMap[cfgPolicy]
		if !ok {
			return nil, common.NewError(events.AccessRecord_BundleReference_NOTFOUND_ERROR, fmt.Sprintf("role not found 2: %s", mrn))
		}

		annotations := map[string]string{"common": "\"but in quoted role annotation\"", "common_to_role_group": "\"but in role\"", "rolekey": "1"}
		return b.generatePolicyReference(ctx, mrn, toStringArray(policies.([]interface{}))[0], annotations)
	}

	logger.Debugf(mockAgent, "getRole", "no roles found for: %s", mrn)
	return nil, common.NewError(events.AccessRecord_BundleReference_NOTFOUND_ERROR, fmt.Sprintf("role not found 3: %s", mrn))
}

// GetGroup retrieves a group by its MRN from the mock backend configuration.
func (b *Backend) GetGroup(ctx context.Context, mrn string) (*model.Group, *common.PolicyError) {
	if strings.Contains(mrn, "networkerror") {
		return nil, &common.PolicyError{ReasonCode: events.AccessRecord_BundleReference_NETWORK_ERROR, Reason: "network error"}
	}

	groupConfig := config.VConfig.Get(fmt.Sprintf("%s.groups", mockDomainCfg))
	if groupConfig == nil {
		return nil, common.NewError(events.AccessRecord_BundleReference_NOTFOUND_ERROR, fmt.Sprintf("group not found: %s", mrn))
	}

	for _, group := range groupConfig.([]interface{}) {
		groupMap := group.(map[string]interface{})
		_rmrn, ok := groupMap[cfgMrn]
		if !ok || mrn != _rmrn.(string) {
			continue
		}

		roles, ok := groupMap[cfgRole]
		if !ok {
			return nil, common.NewError(events.AccessRecord_BundleReference_NOTFOUND_ERROR, fmt.Sprintf("group not found: %s", mrn))
		}

		return &model.Group{
			Mrn:         mrn,
			Roles:       toStringArray(roles.([]interface{})),
			Annotations: model.UnsafeToJSON(map[string]string{"common": "\"but in quoted group annotation\"", "common_to_role_group": "\"group\"", "groupkey": "1"}),
		}, nil
	}

	return nil, common.NewError(events.AccessRecord_BundleReference_NOTFOUND_ERROR, fmt.Sprintf("group not found: %s", mrn))
}

// GetScope retrieves a scope by its MRN from the mock backend configuration.
func (b *Backend) GetScope(ctx context.Context, mrn string) (*model.PolicyReference, *common.PolicyError) {
	if strings.Contains(mrn, "networkerror") {
		return nil, &common.PolicyError{ReasonCode: events.AccessRecord_BundleReference_NETWORK_ERROR, Reason: "network error"}
	}

	scopeConfig := config.VConfig.Get(fmt.Sprintf("%s.scopes", mockDomainCfg))
	if scopeConfig == nil {
		return nil, common.NewError(events.AccessRecord_BundleReference_NOTFOUND_ERROR, fmt.Sprintf("scopes not found: %s", mrn))
	}
	logger.Debugf(mockAgent, "getScope", "read scopeConfig: %+v", scopeConfig.([]interface{}))

	for _, scope := range scopeConfig.([]interface{}) {
		scopeMap := scope.(map[string]interface{})
		logger.Debugf(mockAgent, "getScope", "scopes: %+v", scopeMap)

		_rmrn, ok := scopeMap[cfgMrn]
		if !ok || mrn != _rmrn.(string) {
			logger.Debugf(mockAgent, "getScope", "mrn: %s not equal %s", _rmrn.(string), mrn)
			continue
		}

		policies, ok := scopeMap[cfgPolicy]
		if !ok {
			return nil, common.NewError(events.AccessRecord_BundleReference_NOTFOUND_ERROR, fmt.Sprintf("scopes not found: %s", mrn))
		}

		annotations := map[string]string{"common": "\"quoted scope annotation\"", "scopekey": "1"}
		return b.generatePolicyReference(ctx, mrn, toStringArray(policies.([]interface{}))[0], annotations)
	}

	logger.Debugf(mockAgent, "getScope", "no scopes found for: %s", mrn)
	return nil, common.NewError(events.AccessRecord_BundleReference_NOTFOUND_ERROR, fmt.Sprintf("scopes not found: %s", mrn))
}

// GetResource retrieves a resource by its MRN from the mock backend configuration.
func (b *Backend) GetResource(ctx context.Context, mrn string) (*model.Resource, *common.PolicyError) {
	if strings.Contains(mrn, "networkerror") {
		return nil, &common.PolicyError{ReasonCode: events.AccessRecord_BundleReference_NETWORK_ERROR, Reason: "network error"}
	}

	// Resource not found.  Return resource with default resource group
	defaultResource := &model.Resource{
		ID:          mrn,
		Group:       "mrn:iam:manetu.io:resource-group:default",
		Owner:       "",
		Annotations: model.UnsafeToJSON(map[string]string{"foo": "\"quoted foo\"", "bar": "1", "foobar": "{\"x\": \"double quoted x\"}"}),
	}
	if mrn == "mrn:vault:bar:unquoted" {
		defaultResource.Annotations = model.UnsafeToJSON(map[string]string{"foo": "unquoted foo", "bar": "1"})
	}

	rConfig := config.VConfig.Get(fmt.Sprintf("%s.resources", mockDomainCfg))
	if rConfig != nil {

		logger.Debugf(mockAgent, "getResource", "read rConfig: %+v", rConfig.([]interface{}))

		for _, res := range rConfig.([]interface{}) {
			rmap := res.(map[string]interface{})
			rmrn, ok := rmap[cfgMrn].(string)
			if !ok || rmrn != mrn {
				continue
			}

			rmeta, ok := rmap[cfgMetadata].(map[string]interface{})
			if !ok {
				continue
			}

			x, _ := rmeta[cfgAnnotations].(map[string]interface{})
			annots := make(map[string]string)
			for k, v := range x {
				if s, ok := v.(string); ok {
					annots[k] = s
				}
			}

			jsonAnnots, err := model.ToJSON(annots)
			if err != nil {
				logger.Errorf(mockAgent, "getResource", "error converting annotations to json: %s", err)
				return nil, err
			}

			myresource := &model.Resource{
				ID:             rmrn,
				Owner:          rmeta[cfgOwner].(string),
				Group:          rmeta[cfgGroup].(string),
				Annotations:    jsonAnnots,
				Classification: rmeta[cfgClassification].(string),
			}
			logger.Debugf(mockAgent, "getResource", "myresource: %s", myresource)
			return myresource, nil
		}
	} else {
		// Cannot read from config, return default resource group
		logger.Debugf(mockAgent, "getResource", "Returning default test resource %+v", mrn)
	}

	logger.Debugf(mockAgent, "getResource", "no rgs found for: %s.  Returning default group", mrn)
	return defaultResource, nil
}

// GetResourceGroup retrieves a resource group by its MRN from the mock backend configuration.
func (b *Backend) GetResourceGroup(ctx context.Context, mrn string) (*model.PolicyReference, *common.PolicyError) {
	rgConfig := config.VConfig.Get(fmt.Sprintf("%s.resourcegroups", mockDomainCfg))
	if rgConfig == nil {
		return nil, common.NewError(events.AccessRecord_BundleReference_NOTFOUND_ERROR, fmt.Sprintf("rg not found: %s", mrn))
	}
	logger.Debugf(mockAgent, "getResourceGroup", "read rgConfig: %+v", rgConfig.([]interface{}))

	for _, rg := range rgConfig.([]interface{}) {
		rgMap := rg.(map[string]interface{})
		logger.Debugf(mockAgent, "getResourceGroup", "rgs: %+v", rgMap)

		_rmrn, ok := rgMap[cfgMrn]
		if !ok || mrn != _rmrn.(string) {
			logger.Debugf(mockAgent, "getResourceGroup", "mrn: %s not equal %s", _rmrn.(string), mrn)
			continue
		}

		policies, ok := rgMap[cfgPolicy]
		if !ok {
			return nil, common.NewError(events.AccessRecord_BundleReference_NOTFOUND_ERROR, fmt.Sprintf("rg not found: %s", mrn))
		}

		annot := map[string]string{}
		if mrn == "mrn:iam:manetu.io:resource-group:default" {
			annot = map[string]string{"foo": "\"quoted foo\""}
		}

		return b.generatePolicyReference(ctx, mrn, toStringArray(policies.([]interface{}))[0], annot)
	}
	logger.Debugf(mockAgent, "getResourceGroup", "no rgs found for: %s", mrn)

	return nil, common.NewError(events.AccessRecord_BundleReference_NOTFOUND_ERROR, fmt.Sprintf("rg not found: %s", mrn))
}

// GetOperation retrieves an operation by its MRN from the mock backend configuration.
func (b *Backend) GetOperation(ctx context.Context, mrn string) (*model.PolicyReference, *common.PolicyError) {
	opConfig := config.VConfig.Get(fmt.Sprintf("%s.operations", mockDomainCfg))
	if opConfig == nil {
		return nil, common.NewError(events.AccessRecord_BundleReference_NOTFOUND_ERROR, fmt.Sprintf("operation not found: %s", mrn))
	}
	logger.Debugf(mockAgent, "GetOperationComposition", "op configs: %+v", opConfig)
	for _, op := range opConfig.([]interface{}) {
		opMap := op.(map[string]interface{})
		selectors, ok := opMap[cfgSelector]
		if !ok || !matchSelectors(mrn, convertSelectors(selectors.([]interface{}))) {
			continue
		}

		policies, ok := opMap[cfgPolicy]
		if !ok {
			return nil, common.NewError(events.AccessRecord_BundleReference_NOTFOUND_ERROR, fmt.Sprintf("operation not found: %s", mrn))
		}

		return b.generatePolicyReference(ctx, mrn, toStringArray(policies.([]interface{}))[0], map[string]string{})
	}

	return nil, common.NewError(events.AccessRecord_BundleReference_NOTFOUND_ERROR, fmt.Sprintf("operation not found: %s", mrn))
}

// GetMapper retrieves a mapper for the specified domain from the mock backend configuration.
func (b *Backend) GetMapper(ctx context.Context, domainName string) (*model.Mapper, *common.PolicyError) {
	mapperConfig := config.VConfig.Get(fmt.Sprintf("%s.mappers", mockDomainCfg))
	if mapperConfig == nil {
		return nil, common.NewError(events.AccessRecord_BundleReference_NOTFOUND_ERROR, "no mappers found in mock domain")
	}

	// Handle both []interface{} (from YAML config) and []map[string]interface{} (from programmatic config)
	var mapperMap map[string]interface{}
	switch v := mapperConfig.(type) {
	case []interface{}:
		if len(v) == 0 {
			return nil, common.NewError(events.AccessRecord_BundleReference_NOTFOUND_ERROR, "no mappers found in mock domain")
		}
		mapperMap = v[0].(map[string]interface{})
	case []map[string]interface{}:
		if len(v) == 0 {
			return nil, common.NewError(events.AccessRecord_BundleReference_NOTFOUND_ERROR, "no mappers found in mock domain")
		}
		mapperMap = v[0]
	default:
		return nil, common.NewError(events.AccessRecord_BundleReference_NOTFOUND_ERROR, fmt.Sprintf("invalid mapper config type: %T", mapperConfig))
	}

	// Get mapper name and rego
	mapperName, ok := mapperMap["name"]
	if !ok {
		return nil, common.NewError(events.AccessRecord_BundleReference_NOTFOUND_ERROR, "mapper name not found")
	}

	regoCode, ok := mapperMap["rego"]
	if !ok {
		// Try rego_filename
		regoFilename, ok := mapperMap["rego_filename"]
		if !ok {
			return nil, common.NewError(events.AccessRecord_BundleReference_NOTFOUND_ERROR, "mapper rego not found")
		}
		// Read from file
		configfilename := config.VConfig.ConfigFileUsed()
		dir := filepath.Dir(configfilename)
		filedata, err := os.ReadFile(filepath.Clean(dir + string(filepath.Separator) + regoFilename.(string)))
		if err != nil {
			return nil, common.NewError(events.AccessRecord_BundleReference_NOTFOUND_ERROR, fmt.Sprintf("failed to read mapper file: %s", err))
		}
		regoCode = string(filedata)
	}

	regoStr := regoCode.(string)
	if len(regoStr) == 0 {
		return nil, common.NewError(events.AccessRecord_BundleReference_NOTFOUND_ERROR, "mapper rego is empty")
	}

	// Compile the mapper
	mapperID := fmt.Sprintf("mapper.%s", mapperName.(string))
	modules := map[string]string{
		mapperID: regoStr,
	}

	ast, err := b.mapperCompiler.Compile(mapperID, modules)
	if err != nil {
		return nil, common.NewError(events.AccessRecord_BundleReference_COMPILATION_ERROR, fmt.Sprintf("compilation failed: %s", err))
	}

	// Use empty domain name for mock (domainName parameter is ignored in mock mode)
	return &model.Mapper{
		Domain: "",
		Ast:    ast,
	}, nil
}
