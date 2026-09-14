package intake

import (
	_ "embed"

	"gopkg.in/yaml.v3"
)

//go:embed defaults.yaml
var defaultsYAML []byte

// EgressTarget is one external endpoint, carrying the consequence of losing it
// so a failure names what breaks rather than just which host was unreachable.
type EgressTarget struct {
	URL         string `yaml:"url"`
	Label       string `yaml:"label"`
	When        string `yaml:"when"` // install | runtime | optional
	Consequence string `yaml:"consequence"`
}

type TCPTarget struct {
	Host        string `yaml:"host"`
	Port        int    `yaml:"port"`
	Label       string `yaml:"label"`
	When        string `yaml:"when"`
	Consequence string `yaml:"consequence"`
}

type RegistryEntry struct {
	Host        string `yaml:"host"`
	PulledBy    string `yaml:"pulledBy"`
	Requirement string `yaml:"requirement"` // required | conditional | dormant
	Feature     string `yaml:"feature,omitempty"`
}

// Profile holds the floors an operator cannot reasonably be asked for. It seeds
// the intake form; it is not the source of truth for capacity.
type Profile struct {
	ImageFsGi          int `yaml:"imageFsGi"`
	BaseStorageGi      int `yaml:"baseStorageGi"`
	DataStoreStorageGi int `yaml:"dataStoreStorageGi"`
	ClickHouseGiPerDay int `yaml:"clickHouseGiPerDay"`

	MinNodes           int     `yaml:"minNodes"`
	MinNodesWithAddons int     `yaml:"minNodesWithAddons"`
	BaseCPUCores       float64 `yaml:"baseCpuCores"`
	BaseMemoryGi       float64 `yaml:"baseMemoryGi"`
	LargestPodMemoryGi float64 `yaml:"largestPodMemoryGi"`
	LargestPodCPU      float64 `yaml:"largestPodCpuCores"`

	MinKubernetes string `yaml:"minKubernetes"`
	MinOpenShift  string `yaml:"minOpenShift"`

	HFThroughputMBs float64 `yaml:"hfThroughputMBs"`
	ClockSkewWarnS  int     `yaml:"clockSkewWarnSeconds"`
	ClockSkewFailS  int     `yaml:"clockSkewFailSeconds"`

	AppsetComponents []string        `yaml:"appsetComponents"`
	Registries       []RegistryEntry `yaml:"registries"`
	Egress           []EgressTarget  `yaml:"egress"`
	EgressTCP        []TCPTarget     `yaml:"egressTcp"`
	CatalogVersion   string          `yaml:"catalogVersion"`
}

func LoadProfile() (Profile, error) {
	var p Profile
	err := yaml.Unmarshal(defaultsYAML, &p)
	return p, err
}

// IsAppsetComponent reports whether a component is installed by the
// ApplicationSets and is therefore NOT a prerequisite (FRD-020 §3.1).
func (p Profile) IsAppsetComponent(name string) bool {
	for _, c := range p.AppsetComponents {
		if c == name {
			return true
		}
	}
	return false
}
