package abe

const (
	//coreABEGroupKeyPath is where the BASE EC element is stored
	coreABEGroupKeyPath = "config/ecelement"

	authority_init            = "authority"
	AuthoritiesPath           = "authority_keys"
	SystemAttributes          = "SYSTEM_ATTRIBUTES"
	SystemAttributesEndpoint  = "systemattributes"
	keypath                   = "/KEYS/"
	genpath                   = "subject"
	keypathGids               = "/GIDS/"
	keygenpath                = "keygen"
	systemattributekeygenpath = "syskeygen"
	majorityConcernsDir       = "majority_concerns"
	abecache                  = "ecData"
	privateAccessor            = "PRIVATE_DATA"
	publicAccessor           = "PUBLISHED_DATA"
	CommonAttributes          = "COMMON_AUTHORITIES_ATTRIBUTES"
	CommonAttributesEndpoint  = "commonattributes"
)

type encodedG struct {
	EncodedG []byte
	Params   []byte
}

type mergedAttributes struct {
	attribute string
	isCommon  bool
}

type majorityConcernsInfo struct {
	Attribute map[string]map[string][]string
}

type keysData struct {
	Attribute string `json:"Attribute"`
	Alphai    []byte `json:"alphai"`
	Yi        []byte `json:"yi"`
}

type keysDataAsResponse struct {
	Attribute string `json:"Attribute"`
	Alphai    string `json:"alphai"`
	Yi        string `json:"yi"`
}

type gidData struct {
	GID                  string                       `json:"GID"`
	COMMON_ATTRIBUTES    map[string][]byte            `json:"COMMON_ATTRIBUTES"`
	AUTHORITY_ATTRIBUTES map[string]map[string][]byte `json:"AUTHORITY_ATTRIBUTES"`
	// SYSTEM_ATTRIBUTES    map[string][]byte            `json:"SYSTEM_ATTRIBUTES"`
	SYSTEM_ATTRIBUTES    []string `json:"SYSTEM_ATTRIBUTES"`
}

type cryptogram struct {
	C0               []byte            `json:"C0"`
	C1               map[string][]byte `json:"C1"`
	C2               map[string][]byte `json:"C2"`
	C3               map[string][]byte `json:"C3"`
	SysDecrypted     []byte            `json:"SysDecrypted,omitempty"`
	EncryptedMessage []byte            `json:"EncryptedMessage"`
	CipherIV         []byte            `json:"CipherIV"`
	PolicyStr        string            `json:"Policy"`
}
