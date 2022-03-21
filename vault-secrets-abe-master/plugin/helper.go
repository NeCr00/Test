package abe

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/Nik-U/pbc"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/jsonutil"
	"github.com/hashicorp/vault/sdk/logical"
)

func (b *backend) createHashMapper(ecElement *pbc.Element) func(GID string) *pbc.Element {
	hash := sha256.New()

	mapper := func(GID string) *pbc.Element {
		hash.Reset()
		hash.Write([]byte(GID))

		mapGID := ecElement.Pairing().NewG1()
		mapGID.SetFromHash(hash.Sum([]byte(GID)))

		return mapGID
	}

	return mapper
}

func (b *backend) loadEC(ctx context.Context) (*pbc.Element, error) {

	out, err := b.storage.Get(ctx, coreABEGroupKeyPath)

	if err != nil {
		return nil, errwrap.Wrapf("read failed: {{err}}", err)
	}

	if out == nil {
		return nil, nil
	}

	var ecData encodedG
	if err := jsonutil.DecodeJSON(out.Value, &ecData); err != nil {
		return nil, errwrap.Wrapf("json decoding failed: {{err}}", err)
	}

	ecParams := string([]byte(ecData.Params))

	loadedParams, _ := pbc.NewParamsFromString(ecParams)

	pairing := loadedParams.NewPairing()

	element := pairing.NewG1().SetCompressedBytes(ecData.EncodedG)

	return element, nil
}

func (b *backend) getKeyData(ctx context.Context, req *logical.Request, attribute string, authority string, isCommon bool, isSystemAttribute bool, needPrivateKeys bool) (*pbc.Element, *pbc.Element, error) {

	var dataLocation string
	var ecElement = b.getABEElement()
	var endpoint = attribute
	var accessor string
	if !strings.HasSuffix(endpoint, "/") {
		endpoint = endpoint + "/"
	}

	path := ""
	if isCommon && !isSystemAttribute {
		path = "/" + CommonAttributes + "/"
	} else if !isCommon && !isSystemAttribute {
		path = "/" + authority + "/"
	} else if !isCommon && isSystemAttribute {
		path = "/" + SystemAttributes + "/"
	}
	if needPrivateKeys {
		accessor = publicAccessor
	} else {
		accessor = privateAccessor
	}
	if path != "" {
		dataLocation = AuthoritiesPath + path + endpoint + accessor
	} else {
		return nil, nil, nil //Should return an error
	}

	out, err := b.storage.Get(ctx, dataLocation)

	if err != nil {
		return nil, nil, errwrap.Wrapf("read failed: {{err}}", err)
	}

	// Fast-path the no data case
	if out == nil {
		return nil, nil, nil
	}

	// Decode the data
	var data keysData
	if err := jsonutil.DecodeJSON(out.Value, &data); err != nil {
		return nil, nil, errwrap.Wrapf("json decoding failed: {{err}}", err)
	}

	alphai := ecElement.Pairing().NewZr().SetBytes(data.Alphai)
	yi := ecElement.Pairing().NewZr().SetBytes(data.Yi)

	return alphai, yi, nil
}

func (b *backend) loadGIDData(ctx context.Context, req *logical.Request, endpoint string) (gidData, error) {

	var data gidData

	// Read the path
	out, err := req.Storage.Get(ctx, genpath+keypathGids+endpoint)

	if err != nil {
		return data, errwrap.Wrapf("read failed: {{err}}", err)
	}

	// Fast-path the no data case
	if out == nil {
		return data, nil
	}

	if err := jsonutil.DecodeJSON(out.Value, &data); err != nil {
		return data, errwrap.Wrapf("json decoding failed: {{err}}", err)
	}

	return data, nil
}

func (b *backend) separateAuthorityFromAttribute(authorityAttribute string) (string, string, error) {
	delimiter := "["

	attribute := strings.Split(authorityAttribute, delimiter)[0]
	authority := strings.Split(authorityAttribute, attribute)[1]

	regex, err := regexp.Compile(`[^\w]`)

	if err != nil {
		return "", "", errwrap.Wrapf("Internal error {{err}}", err)
	}

	authority = regex.ReplaceAllString(authority, "")

	return strings.ToUpper(authority), strings.ToUpper(attribute), nil

}

func (b *backend) compressedECToElement(ctx context.Context, req *logical.Request, bytesEC []byte, ecElement *pbc.Element) (*pbc.Element, error) {

	return ecElement.Pairing().NewG1().SetCompressedBytes(bytesEC), nil
}

func (b *backend) dataStore(ctx context.Context, data interface{}, pathOptions ...string) error {

	//pathOptions must always be like:
	//pathOptions[0] must be the prePathType
	//pathOptions[1]...[n-1] can be any other option we may need
	//E.g. pathOptions[1] could be "endpoint"

	if pathOptions[0] == "" {
		return errors.New("Error in path options")
	}

	var prePathType = pathOptions[0]

	var storageLocation = ""

	buf, err := json.Marshal(data)

	if err != nil {
		return errwrap.Wrapf("json encoding failed: {{err}}", err)
	}

	if prePathType == coreABEGroupKeyPath {
		storageLocation = coreABEGroupKeyPath
		goto DONE_CHECKING
	}

	if prePathType == genpath {
		GID := data.(gidData).GID
		storageLocation = prePathType + keypathGids + GID
	} else if prePathType == majorityConcernsDir {
		storageLocation = prePathType
	} else {
		storageLocation = prePathType + pathOptions[1] + pathOptions[2]
	}

DONE_CHECKING:
	entry := &logical.StorageEntry{
		Key:   storageLocation,
		Value: buf,
	}

	if err := b.storage.Put(ctx, entry); err != nil {
		return errwrap.Wrapf("failed to write: {{err}}", err)
	}

	return nil
}

func (b *backend) dataKeyStore(ctx context.Context, publishedData interface{}, privateData interface{}, path string, endpoint string) error {

	var storageLocationPublished string
	var storageLocationPrivate string

	if !strings.HasPrefix(privateAccessor, "/") && !strings.HasSuffix(path, "/") {
		endpoint = "/" + endpoint + "/"
	}

	buffer_published, err := json.Marshal(publishedData)
	if err != nil {
		return err
	}

	buffer_private, err := json.Marshal(privateData)
	if err != nil {
		return err
	}

	storageLocationPublished = path + endpoint + privateAccessor
	storageLocationPrivate = path + endpoint + publicAccessor

	publishedEntry := &logical.StorageEntry{
		Key:   storageLocationPublished,
		Value: buffer_published,
	}

	privateEntry := &logical.StorageEntry{
		Key:   storageLocationPrivate,
		Value: buffer_private,
	}

	if err := b.storage.Put(ctx, publishedEntry); err != nil {
		return err
	}
	if err := b.storage.Put(ctx, privateEntry); err != nil {
		b.storage.Delete(ctx, storageLocationPublished)
		return err
	}

	return nil
}

func (b *backend) getABEElement() *pbc.Element {

	element, exists := b.abeCache.Get(abecache)

	if !exists {
		b.abeCache.SetDefault(abecache, nil)
	}

	ecElement := element.(*pbc.Element)

	return ecElement
}

func (b *backend) handleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	if req.ClientToken == "" {
		return nil, fmt.Errorf("client token empty")
	}

	// Read the path
	out, err := req.Storage.Get(ctx, req.Path)
	if err != nil {
		return nil, errwrap.Wrapf("read failed: {{err}}", err)
	}

	// Fast-path the no data case
	if out == nil {
		return nil, nil
	}

	// Decode the data
	var rawData map[string]interface{}
	if err := jsonutil.DecodeJSON(out.Value, &rawData); err != nil {
		return nil, errwrap.Wrapf("json decoding failed: {{err}}", err)
	}

	// Generate the response
	resp := &logical.Response{
		Data: rawData,
	}

	return resp, nil
}

func (b *backend) handleList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	if req.ClientToken == "" {
		return nil, fmt.Errorf("client token empty")
	}

	keys, err := req.Storage.List(ctx, req.Path)

	if err != nil {
		return nil, err
	}

	strippedKeys := make([]string, len(keys))
	for i, key := range keys {
		strippedKeys[i] = strings.ToUpper(strings.TrimPrefix(key, req.Path))
	}

	// Generate the response
	return logical.ListResponse(strippedKeys), nil

}

func (b *backend) pathList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	path := req.Path

	if path != "" && !strings.HasSuffix(path, "/") {
		path = path + "/"
	}

	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	entries, err := req.Storage.List(ctx, path)
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

func (b *backend) constructPath(pathAr []string) string {
	path := ""

	for pos, pathObject := range pathAr {
		path += pathObject
		if pos < len(pathAr)-1 {
			path += "/"
		}
	}

	return path
}

func (b *backend) getEntries(ctx context.Context, pathAr []string) ([]string, error) {
	path := ""

	for pos, pathObject := range pathAr {
		path += pathObject
		if pos < len(pathAr)-1 {
			path += "/"
		}
	}

	entries, err := b.storage.List(ctx, path)
	if err != nil {
		return nil, err
	}

	var modifiedEntries []string

	for _, entry := range entries {
		entry = strings.TrimSuffix(entry, "/")
		entry = strings.TrimPrefix(entry, "/")

		modifiedEntries = append(modifiedEntries, entry)
	}

	return modifiedEntries, nil
}

func (b *backend) checkAttrExistence(aggregratedValues []string, values []string) ([]string, bool) {
	var items []string
	for _, itemValueAggregated := range aggregratedValues {
		for _, itemValue := range values {
			if strings.EqualFold(strings.ToUpper(itemValueAggregated), strings.ToUpper(itemValue)) {
				items = append(items, itemValue)
				break
			}
		}
	}
	if len(items) > 0 {
		return items, true
	} else {
		return nil, false
	}
}

// func (b *backend) checkIfCommonOrSystemAttr(ctx context.Context, values []string) (bool, bool, error) {
// 	systemAttributeEntries, err := b.getEntries(ctx, []string{AuthoritiesPath, SystemAttribute})
// 	if err != nil {
// 		return false, false, errwrap.Wrapf("read failed: {{err}}", err)
// 	}

// 	var items []string

// 	for _, attribute := range systemAttributeEntries {
// 		for _, value := range values {
// 			if value == attribute {
// 				items = append(items, value)
// 				break
// 			}
// 		}
// 	}

// 	//IF len(values) == len(items) => that means that all the given attributes are SYSTEM Attributes
// 	//IF len(values) > len(items) BUT len(items) != 0, that means that the given attributes are BOTH SYSTEM Attributes, COMMON/AUTHORITY Attributes or UNKNOWN Attributes - We should interrupt the process!
// 	//IF len(items) == 0, then we can continue and aggregrate all the available COMMON/AUTHORITY Attributes and the Attributes given to the
// }

func (b *backend) checkNonExistentAttr(aggregratedValues []string, valuesToCheck []string) ([]string, bool) {
	var items []string
	if aggregratedValues == nil {
		return valuesToCheck, true
	}
	for _, itemValue := range valuesToCheck {
		for i, itemValueAggregated := range aggregratedValues {
			if strings.EqualFold(strings.ToUpper(itemValue), strings.ToUpper(itemValueAggregated)) {
				break
			}
			if i == len(aggregratedValues)-1 {
				items = append(items, itemValue)
			}
		}
	}

	if len(items) > 0 {
		return items, true
	} else {
		return nil, false
	}
}

func (b *backend) attributeNotASystemAttribute(ctx context.Context, authorityAttributes []string, commonAttributes []string) ([]string, bool, error) {
	systemAttributeEntries, err := b.getEntries(ctx, []string{AuthoritiesPath, SystemAttributes})
	if err != nil {
		return nil, true, errwrap.Wrapf("read failed: {{err}}", err)
	}

	var items []string

	for _, systemAttribute := range systemAttributeEntries {
		if len(authorityAttributes) > 0 {
			for _, value := range authorityAttributes {
				if systemAttribute == value {
					items = append(items, value)
				}
			}
		}

		if len(commonAttributes) > 0 {
			for _, value := range commonAttributes {
				if systemAttribute == value {
					items = append(items, value)
				}
			}
		}
	}

	if len(items) > 0 {
		return items, true, nil
	} else {
		return nil, false, nil
	}
}

func (b *backend) allAttributesPutTogether(ctx context.Context, req *logical.Request) (map[string]keysData, error) {
	entries, err := b.getEntries(ctx, []string{AuthoritiesPath})
	if err != nil {
		return nil, errwrap.Wrapf("read failed: {{err}}", err)
	}

	data := make(map[string]keysData)

	for _, entry := range entries {
		attributeEntries, err := b.getEntries(ctx, []string{AuthoritiesPath, entry})

		if err != nil {
			return nil, errwrap.Wrapf("read failed: {{err}}", err)
		}

		for _, attributeEntry := range attributeEntries {
			entryAsDir := "/" + entry + "/"
			attributeEntryAsDir := attributeEntry + "/"

			var newData keysData

			out, err := req.Storage.Get(ctx, AuthoritiesPath+entryAsDir+attributeEntryAsDir+privateAccessor)

			if err != nil || out == nil {
				return nil, errwrap.Wrapf("read failed: {{err}}", err)
			}

			if err := jsonutil.DecodeJSON(out.Value, &newData); err != nil {
				return nil, errwrap.Wrapf("json decoding failed: {{err}}", err)
			}

			if (entry != SystemAttributes && entry != CommonAttributes) {
				attributeEntry = attributeEntry + "[" + strings.ToUpper(entry) + "]"
			}

			data[attributeEntry] = newData 
		}
	}

	return data, nil
}

func (b *backend) checkAttributesAvailability(attributes map[string]*pbc.Element, attributesList map[string]keysData) (bool, map[string]struct {
	IsAvailable bool "json:\"IsAvailable\""
}) {

	isThereUnavailableAttr := false

	notAvailableAttributesResponse := make(map[string]struct {
		IsAvailable bool "json:\"IsAvailable\""
	})

	for attr := range attributes {
		attribute := strings.ToUpper(attr)

		if attributesList[attribute].Alphai == nil || attributesList[attribute].Yi == nil {
			isThereUnavailableAttr = true
			notAvailableAttributesResponse[attribute] = struct {
				IsAvailable bool "json:\"IsAvailable\""
			}{
				IsAvailable: false,
			}
		} else {
			notAvailableAttributesResponse[attribute] = struct {
				IsAvailable bool "json:\"IsAvailable\""
			}{
				IsAvailable: true,
			}
		}
	}

	return isThereUnavailableAttr, notAvailableAttributesResponse
}

func (b *backend) mergeCommonAndAuthorityAttributes(ctx context.Context, mergedAttrs *[]*mergedAttributes, directory string, attributes []string, newAddition bool) (bool, string, error) {
	isCommon := false
	if directory == CommonAttributes {
		isCommon = true
	}
	var storedAttributes []string
	storedAttributes, err := b.getEntries(ctx, []string{AuthoritiesPath, directory})
	if err != nil {
		return false, "", err
	}

	if newAddition {
		attributeCheck, attrAlreadyExist := b.checkAttrExistence(storedAttributes, attributes)
		message := fmt.Sprintf("%s", attributeCheck)
		if attrAlreadyExist {
			return attrAlreadyExist, message, nil
		}
	} else {
		attributeCheck, attrDontExist := b.checkNonExistentAttr(storedAttributes, attributes)
		if attrDontExist {
			message := fmt.Sprintf("%s", attributeCheck)
			return attrDontExist, message, nil
		}
	}

	for _, attribute := range attributes {
		var newAttribute mergedAttributes
		newAttribute.attribute = attribute
		newAttribute.isCommon = isCommon
		*mergedAttrs = append(*mergedAttrs, &newAttribute)
	}
	return false, "", nil
}

func sliceContains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}
	return false
}