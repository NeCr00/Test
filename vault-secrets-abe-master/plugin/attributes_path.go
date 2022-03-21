package abe

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathAttributes(b *backend) []*framework.Path {

	return []*framework.Path{
		{
			Pattern: "authorityattributes" + "/" + framework.GenericNameRegex("authority_name"),

			Fields: map[string]*framework.FieldSchema{
				"authority_name": {
					Type:        framework.TypeString,
					Description: "The authority to which the derived attributes correspond to",
					Required:    true,
				},
			},

			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.getAuthorityAttributes,
				logical.CreateOperation: b.getAuthorityAttributes,
			},
		},
		{
			Pattern: "authorityattributes" + "/" + framework.GenericNameRegex("authority_name") + "/" + framework.GenericNameRegex("attribute_name"),

			Fields: map[string]*framework.FieldSchema{
				"authority_name": {
					Type:        framework.TypeString,
					Description: "The authority to which the derived attribute corresponds to",
					Required:    true,
				},
				"attribute_name": {
					Type:        framework.TypeString,
					Description: "The attribute's name",
					Required:    true,
				},
			},

			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.getDistinctAuthorityAttribute,
				logical.CreateOperation: b.getDistinctAuthorityAttribute,
			},
		},
		{
			Pattern: "attributes" + "/" + framework.GenericNameRegex("attribute_type"),

			Fields: map[string]*framework.FieldSchema{
				"attribute_type": {
					Type:        framework.TypeString,
					Description: "The desired type of the attributes (Accepts 2 types: `systemattributes` for System Attributes and `commonattributes` for Common Attributes)",
					Required:    true,
				},
			},

			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.getAttributes,
				logical.CreateOperation: b.getAttributes,
			},
		},
		{
			Pattern: "attributes" + "/" + framework.GenericNameRegex("attribute_type") + "/" + framework.GenericNameRegex("attribute_name"),

			Fields: map[string]*framework.FieldSchema{
				"attribute_type": {
					Type:        framework.TypeString,
					Description: "The type of the attribute (Accepts 2 types: `systemattributes` for System Attributes and `commonattributes` for Common Attributes)",
					Required:    true,
				},
				"attribute_name": {
					Type:        framework.TypeString,
					Description: "The name of the desired attribute",
					Required:    true,
				},
			},

			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.getDistinctAttribute,
				logical.CreateOperation: b.getDistinctAttribute,
			},
		},
	}
}

func (b *backend) getDistinctAuthorityAttribute(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	authority_name := data.Get("authority_name").(string)
	attribute_name := strings.ToUpper(data.Get("attribute_name").(string))

	alphai, yi, err := b.getKeyData(ctx, req, attribute_name, authority_name, false, false, false)
	if err != nil {
		return nil, errwrap.Wrapf("existence check failed: {{err}}", err)
	}

	if alphai == nil || yi == nil {
		return logical.ErrorResponse("An attribute with the identifier %s does not exist for the authority %s", attribute_name, authority_name), nil
	}

	var publishedDataResponse = struct {
		Alphai string "json:\"alphai\""
		Yi     string "json:\"yi\""
	}{
		Alphai: alphai.String(),
		Yi:     yi.String(),
	}

	return &logical.Response{
		Data: map[string]interface{}{
			attribute_name: publishedDataResponse,
		},
	}, nil
}

func (b *backend) getAuthorityAttributes(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	authority_name := data.Get("authority_name").(string)

	attributes, err := b.getEntries(ctx, []string{AuthoritiesPath, authority_name})
	if err != nil {
		return nil, errwrap.Wrapf("existence check failed: {{err}}", err)
	}

	if len(attributes) == 0 {
		return logical.ErrorResponse("The Authority with name %s does not own any attributes", authority_name), nil
	}

	var publishedDataResponse []map[string]struct {
		Alphai string "json:\"alphai\""
		Yi     string "json:\"yi\""
	}
	for _, attribute := range attributes {
		alphai, yi, err := b.getKeyData(ctx, req, attribute, "", false, false, false)
		if err != nil {
			return nil, err
		}

		attributeToData := make(map[string]struct {
			Alphai string "json:\"alphai\""
			Yi     string "json:\"yi\""
		})

		attributeToData[attribute] = struct {
			Alphai string "json:\"alphai\""
			Yi     string "json:\"yi\""
		}{
			Alphai: alphai.String(),
			Yi:     yi.String(),
		}

		publishedDataResponse = append(publishedDataResponse, attributeToData)

	}

	return &logical.Response{
		Data: map[string]interface{}{
			authority_name: publishedDataResponse,
		},
	}, nil

}

func (b *backend) getDistinctAttribute(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	attribute_type := strings.ToLower(data.Get("attribute_type").(string))
	attribute_name := strings.ToUpper(data.Get("attribute_name").(string))
	var attributeTypeToLoad string
	var commonAttributeBool bool
	var systemAttributeBool bool

	switch attribute_type {
	case CommonAttributesEndpoint:
		attributeTypeToLoad = CommonAttributes
		commonAttributeBool = true
		systemAttributeBool = false
	case SystemAttributesEndpoint:
		attributeTypeToLoad = SystemAttributes
		commonAttributeBool = false
		systemAttributeBool = true
	default:
		attributeTypeToLoad = "UNKNOWN"
	}

	if attributeTypeToLoad == "UNKNOWN" {
		return logical.ErrorResponse(fmt.Sprintf(`Unknown attribute type %s`, attribute_type)), nil
	}

	alphai, yi, err := b.getKeyData(ctx, req, attribute_name, "", commonAttributeBool, systemAttributeBool, false)
	if err != nil {
		return nil, errwrap.Wrapf("existence check failed: {{err}}", err)
	}

	if alphai == nil || yi == nil {
		return logical.ErrorResponse("An attribute with the identifier %s does not exist", attribute_name), nil
	}

	var publishedDataResponse = struct {
		Alphai string "json:\"alphai\""
		Yi     string "json:\"yi\""
	}{
		Alphai: alphai.String(),
		Yi:     yi.String(),
	}

	return &logical.Response{
		Data: map[string]interface{}{
			attribute_name: publishedDataResponse,
		},
	}, nil

}

func (b *backend) getAttributes(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	attribute_type := strings.ToLower(data.Get("attribute_type").(string))
	var attributeTypeToLoad string
	var commonAttributeBool bool
	var systemAttributeBool bool

	switch attribute_type {
	case CommonAttributesEndpoint:
		attributeTypeToLoad = CommonAttributes
		commonAttributeBool = true
		systemAttributeBool = false
	case SystemAttributesEndpoint:
		attributeTypeToLoad = SystemAttributes
		commonAttributeBool = false
		systemAttributeBool = true
	default:
		attributeTypeToLoad = "UNKNOWN"
	}

	if attributeTypeToLoad == "UNKNOWN" {
		return logical.ErrorResponse(fmt.Sprintf(`Unknown attribute type %s`, attribute_type)), nil
	}

	attributes, err := b.getEntries(ctx, []string{AuthoritiesPath, attributeTypeToLoad})
	if err != nil {
		return nil, errwrap.Wrapf("existence check failed: {{err}}", err)
	}

	if len(attributes) == 0 {
		var attributeTypeReconstructed string
		if attributeTypeToLoad == CommonAttributes {
			attributeTypeReconstructed = "Common Attributes"
		} else {
			attributeTypeReconstructed = "System Attributes"
		}
		return logical.ErrorResponse("There are no attributes of type %s", attributeTypeReconstructed), nil
	}

	var publishedDataResponse []map[string]struct {
		Alphai string "json:\"alphai\""
		Yi     string "json:\"yi\""
	}
	for _, attribute := range attributes {
		alphai, yi, err := b.getKeyData(ctx, req, attribute, "", commonAttributeBool, systemAttributeBool, false)
		if err != nil {
			return nil, err
		}

		attributeToData := make(map[string]struct {
			Alphai string "json:\"alphai\""
			Yi     string "json:\"yi\""
		})

		attributeToData[attribute] = struct {
			Alphai string "json:\"alphai\""
			Yi     string "json:\"yi\""
		}{
			Alphai: alphai.String(),
			Yi:     yi.String(),
		}

		publishedDataResponse = append(publishedDataResponse, attributeToData)

	}

	return &logical.Response{
		Data: map[string]interface{}{
			attributeTypeToLoad: publishedDataResponse,
		},
	}, nil

}
