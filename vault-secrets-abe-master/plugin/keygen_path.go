package abe

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/jsonutil"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathKeygenSetup(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: strings.ToLower(keygenpath) + "/" + framework.GenericNameRegex("fromAuthority") + "/" + framework.GenericNameRegex("toGID"),

			Fields: map[string]*framework.FieldSchema{
				"authorityAttributes": {
					Type:        framework.TypeStringSlice,
					Description: "The authority attributes to produce keys for",
					Required:    true,
				},
				"commonAttributes": {
					Type:        framework.TypeStringSlice,
					Description: "The common attributes to produce keys for",
					Required:    true,
				},
				"fromAuthority": {
					Type:        framework.TypeString,
					Description: "The authority that will produce the keys",
					Required:    true,
				},
				"toGID": {
					Type:        framework.TypeString,
					Description: "The GID to produce keys for",
					Required:    true,
				},
			},

			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.keygen,
				logical.CreateOperation: b.keygen,
			},
		},
		{
			Pattern: strings.ToLower(systemattributekeygenpath) + "/" + framework.GenericNameRegex("system_attribute") + "/" + framework.GenericNameRegex("authority"),

			Fields: map[string]*framework.FieldSchema{
				"authority": {
					Type:        framework.TypeString,
					Description: "The authority that will provide other entities with a System Attribute",
					Required:    true,
				},
				"system_attribute": {
					Type:        framework.TypeString,
					Description: "The System attribute to give to another entity",
					Required:    true,
				},
				"authorities": {
					Type:        framework.TypeStringSlice,
					Description: "The authorities to give the attribute to",
					Required:    true,
				},
			},

			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.systemAttributesKeygen,
				logical.CreateOperation: b.systemAttributesKeygen,
			},
		},
		{
			Pattern: majorityConcernsDir,

			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation: b.handleRead,
				logical.ListOperation: b.handleList,
			},
		},
		{
			Pattern: genpath + "/?$",

			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation: b.pathList,
			},
		},
		{
			Pattern: genpath + keypathGids + "/?$",

			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation: b.pathList,
			},
		},
		{
			Pattern: genpath + keypathGids + framework.GenericNameRegex("USER"),
			Fields: map[string]*framework.FieldSchema{
				"path": {
					Type: framework.TypeString,
					Description: `[Required for all types]	Name of the role being created.`,
				},
			},
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation: b.handleRead,
				logical.ListOperation: b.handleList,
			},

			//ExistenceCheck: b.handleExistenceCheck,
		},
	}
}

func (b *backend) keygen(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	authorityAttrs := data.Get("authorityAttributes").([]string)
	commonAttrs := data.Get("commonAttributes").([]string)
	GID := data.Get("toGID").(string)
	authority := data.Get("fromAuthority").(string)

	if len(authorityAttrs) == 0 && len(commonAttrs) == 0 {
		return logical.ErrorResponse("Please, provide some attributes"), nil
	}

	for i := range authorityAttrs {
		authorityAttrs[i] = strings.ToUpper(authorityAttrs[i])
	}
	for i := range commonAttrs {
		commonAttrs[i] = strings.ToUpper(commonAttrs[i])
	}

	gidData, err := b.loadGIDData(ctx, req, GID)
	if err != nil {
		return nil, errwrap.Wrapf("Error with GID data: {{err}}", err)
	}

	if gidData.GID == "" {
		gidData.GID = GID
	}

	mergedAttrs := make([]*mergedAttributes, 0)
	var existenceMessage string
	if len(commonAttrs) > 0 {
		attrsDontExist, message, err := b.mergeCommonAndAuthorityAttributes(ctx, &mergedAttrs, CommonAttributes, commonAttrs, false)
		if err != nil {
			return nil, errwrap.Wrapf("existence check failed: {{err}}", err)
		}
		if attrsDontExist {
			existenceMessage += ("Common Attributes: " + message)
		}
	}
	if len(authorityAttrs) > 0 {
		attrsDontExist, message, err := b.mergeCommonAndAuthorityAttributes(ctx, &mergedAttrs, authority, authorityAttrs, false)
		if err != nil {
			return nil, errwrap.Wrapf("existence check failed: {{err}}", err)
		}
		if attrsDontExist {
			if existenceMessage != "" {
				existenceMessage += " - "
			}
			existenceMessage += ("Authority Attributes: " + message)
		}
	}
	if existenceMessage != "" {
		existenceMessage = fmt.Sprintf("Non-existent attributes: " + existenceMessage)
		return logical.ErrorResponse(existenceMessage), nil
	}

	// Should also check if the GID already owns the attributes (this is not essential)

	ecElement := b.getABEElement()
	
	gidMapper := b.createHashMapper(ecElement)
	hashedGIDInEC := gidMapper(GID)

	for _, mergedAttribute := range mergedAttrs {
		attribute := mergedAttribute.attribute
		isCommonAttribute := mergedAttribute.isCommon

		alphai, yi, err := b.getKeyData(ctx, req, attribute, authority, isCommonAttribute, false, true)
		if err != nil {
			return nil, errwrap.Wrapf("failed: {{err}}", err)
		}

		fieldBase := ecElement.Pairing().NewG1()
		fieldh := ecElement.Pairing().NewG1().Set(hashedGIDInEC).ThenPowZn(yi)
		fieldR := ecElement.Pairing().NewG1().Set(ecElement).ThenPowZn(alphai)

		fieldBase.Set(fieldR).ThenMul(fieldh)

		if isCommonAttribute {
			if gidData.COMMON_ATTRIBUTES == nil {
				gidData.COMMON_ATTRIBUTES = make(map[string][]byte)
			}
			gidData.COMMON_ATTRIBUTES[attribute] = fieldBase.Bytes()
		} else {
			if gidData.AUTHORITY_ATTRIBUTES == nil {
				gidData.AUTHORITY_ATTRIBUTES = make(map[string]map[string][]byte)
			}

			if gidData.AUTHORITY_ATTRIBUTES[authority] == nil {
				gidData.AUTHORITY_ATTRIBUTES[authority] = map[string][]byte{}
			}

			gidData.AUTHORITY_ATTRIBUTES[authority][attribute] = fieldBase.Bytes()
		}
	}

	b.dataStore(ctx, gidData, genpath)

	// Return a response only if there were no problems up till this point.
	return &logical.Response{
		Data: map[string]interface{}{
			"Generated for (GID)":       GID,
			"Authority Keys generated:": authorityAttrs,
			"Common Keys generated:":    commonAttrs,
		},
	}, nil
}

func (b *backend) systemAttributesKeygen(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	authority := data.Get("authority").(string)
	system_attribute := strings.ToUpper(data.Get("system_attribute").(string))
	authorities := data.Get("authorities").([]string)

	if len(authorities) == 0 {
		return logical.ErrorResponse(`Provide authorities' names`), nil
	} else {
		for i := range authorities {
			authorities[i] = authorities[i]
		}
	}

	keys := make(map[string]bool) // Check for duplicates and erase
	var authoritiesList []string
	for _, entry := range authorities {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			authoritiesList = append(authoritiesList, entry)
		}
	}

	authorities = authoritiesList
	authoritiesList = authoritiesList[:0]

	for i, authority := range authorities { // Check for self-vote(s) and, if some exist, erase
		if authority == req.DisplayName {
			authorities[i] = authorities[len(authorities)-1]
			authorities[len(authorities)-1] = ""
			authorities = authorities[:len(authorities)-1]
			continue
		}
	}

	// for i := range authorities { //Just turn to uppercase...
	// 	authorities[i] = strings.ToUpper(authorities[i])
	// }

	out, err := b.storage.Get(ctx, majorityConcernsDir)
	if err != nil {
		return nil, errwrap.Wrapf("read failed: {{err}}", err)
	}

	if out == nil {
		return nil, nil
	}

	var majorityData majorityConcernsInfo
	if err := jsonutil.DecodeJSON(out.Value, &majorityData); err != nil {
		return nil, errwrap.Wrapf("json decoding failed: {{err}}", err)
	}
	if majorityData.Attribute == nil || len(majorityData.Attribute) == 0 {
		return logical.ErrorResponse(`The System does not utilize any System Attributes`), nil
	}

	majorityData.Attribute[system_attribute][authority] = authorities

	b.dataStore(ctx, majorityData, majorityConcernsDir)

	var counterAuthorities float64
	counterVotes := make(map[string]int)

	for _, authorities := range majorityData.Attribute[system_attribute] {
		counterAuthorities++
		for _, authority := range authorities {
			counterVotes[authority] += 1
		}
	}

	// majority := math.Round(counterAuthorities/2) + 1

	ecElement := b.getABEElement()

	gidMapper := b.createHashMapper(ecElement)

	alphai, yi, err := b.getKeyData(ctx, req, system_attribute, "", false, true, true)
	if err != nil {
		return nil, errwrap.Wrapf("failed: {{err}}", err)
	}

	var votedAuthoritiesUpdated []string

	// The below was commented for Development purposes - Remove for production
	// for votedAuthority, votes := range counterVotes {
	// 	if votes >= int(majority) {
	votedAuthority := authority
	votedAuthoritiesUpdated = append(votedAuthoritiesUpdated, votedAuthority)

	gidData, err := b.loadGIDData(ctx, req, votedAuthority)
	if err != nil {
		return nil, errwrap.Wrapf("Error with GID data: {{err}}", err)
	}

	// if gidData.SYSTEM_ATTRIBUTES[system_attribute] == "" {
		hashedGIDInEC := gidMapper(authority)
		fieldBase := ecElement.Pairing().NewG1()
		fieldh := ecElement.Pairing().NewG1().Set(hashedGIDInEC).ThenPowZn(yi)
		fieldR := ecElement.Pairing().NewG1().Set(ecElement).ThenPowZn(alphai)

		fieldBase.Set(fieldR).ThenMul(fieldh)

		if gidData.GID == "" {
			gidData.GID = votedAuthority
		}

		// if gidData.SYSTEM_ATTRIBUTES == nil {
		// 	gidData.SYSTEM_ATTRIBUTES = make(map[string]string)
		// }
		// gidData.SYSTEM_ATTRIBUTES[system_attribute] = fieldBase.Bytes()
		gidData.SYSTEM_ATTRIBUTES = append(gidData.SYSTEM_ATTRIBUTES, system_attribute)
		b.dataStore(ctx, gidData, genpath)
	// }
	// 	}
	// }

	return &logical.Response{
		Data: map[string]interface{}{
			"system_attribute": system_attribute,
			"authorities:":     votedAuthoritiesUpdated,
		},
	}, nil
}
