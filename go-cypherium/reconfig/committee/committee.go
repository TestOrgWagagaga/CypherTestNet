package committee

import (
	"os"

	"github.com/BurntSushi/toml"
	"github.com/dedis/cothority"
	"github.com/dedis/kyber"
	"github.com/dedis/onet/app"
	"github.com/dedis/onet/log"
)

const (
	TomlFileName = "co2/private.toml"
	//TomlFileName1       = "co1/private.toml"
	//TomlFileName2       = "co2/private.toml"
	//TomlFileName3       = "co3/private.toml"
	TomlFileName_Public = "./public.toml"
)

var tSuite = cothority.Suite

type CommitteeInstance interface {
	GetCommitteeMembers() *Committee
	GetCurrentLeaderSeq() int
	GetNextLeaderSeq() int
	GetPrivateSeqInCom(kyber.Point) (int, error)
}

type Committee struct {
	/* Fill the field of the member. */
	Committeemembers map[int]kyber.Point
	CurrentLeaderSeq int
	Group            *app.Group
	groupToml        *app.GroupToml
}

func NewCommittee(publictoml string) (*Committee, error) {
	committee := &Committee{
		Committeemembers: make(map[int]kyber.Point),
		CurrentLeaderSeq: 0,
	}

	log.Lvl1("GetConfig")
	/*TODO: temporary, need change to get from key blocks. */
	f, _ := os.Open(publictoml)

	committee.groupToml = &app.GroupToml{}
	_, err := toml.DecodeReader(f, committee.groupToml)
	if err != nil {
		return nil, err
	}
	//group, _ := app.ReadGroupDescToml(f)
	/*
		servier1 := &app.ServerToml{
			Address:     "tls://192.168.1.103:6879",
			Suite:       "Ed25519",
			Public:      "9e3877e52b90bbfba0176aa10f7340bd4032573f3b1f6daf57e6c6b16045b2ec",
			Description: "leader",
		}
		servier2 := &app.ServerToml{
			Address:     "tls://192.168.1.103:7000",
			Suite:       "Ed25519",
			Public:      "0ee01af829befd3660a36ef5823743dd7465e5bd1829495b1cf909271fccf3ea",
			Description: "leader",
		}

		servier3 := &app.ServerToml{
			Address:     "tls://192.168.1.103:7008",
			Suite:       "Ed25519",
			Public:      "364a1efc5d2dfb0be44bf1d95179a2af3b2a75535fa57e35417e511736661559",
			Description: "leader",
		}
	*/

	//servier1 := &app.ServerToml{"tls://192.168.1.103:6879", "Ed25519", "9e3877e52b90bbfba0176aa10f7340bd4032573f3b1f6daf57e6c6b16045b2ec", "leader"}
	//servier2 := &app.ServerToml{"tls://192.168.1.103:7000", "Ed25519", "0ee01af829befd3660a36ef5823743dd7465e5bd1829495b1cf909271fccf3ea", "slave"}
	//servier3 := &app.ServerToml{"tls://192.168.1.103:7008", "Ed25519", "364a1efc5d2dfb0be44bf1d95179a2af3b2a75535fa57e35417e511736661559", "slave2"}
	//committee.groupToml = app.NewGroupToml(servier1, servier2, servier3)
	//committee.groupToml = app.NewGroupToml(servier1, servier2)

	// temporary get members from public.toml.
	err, group := committee.GetConfig()
	if err != nil {
		panic("Getconfig failed")
	}
	committee.Group = group
	log.Lvl1("GetConfig endif")

	for index, si := range group.Roster.List {
		log.Lvl1("index: ", index, " public:", si.Public)
		committee.Committeemembers[index] = si.Public
	}

	return committee, nil
}

func (committee *Committee) GetConfig() (error, *app.Group) {
	group, _ := app.ReadGroupDescTomlRecofig(committee.groupToml)
	if len(group.Roster.List) == 0 {
		log.Lvl1("Empty entity or invalid group defintion in: %s",
			TomlFileName_Public)
	}

	return nil, group
}

func (committee *Committee) ReconfigCommitteeMembers(servertoml_add *app.ServerToml) (error, *app.Group) {
	committee.groupToml.Servers = append(committee.groupToml.Servers, servertoml_add)
	group, _ := app.ReadGroupDescTomlRecofig(committee.groupToml)
	if len(group.Roster.List) == 0 {
		log.Lvl1("Empty entity or invalid group defintion in: %s",
			TomlFileName_Public)
	}
	committee.Group = group

	for index, si := range group.Roster.List {
		log.Lvl1("index: ", index, " public:", si.Public)
		committee.Committeemembers[index] = si.Public
	}

	return nil, group
}

func (committee *Committee) GetComMembers() map[int]kyber.Point {
	/*TODO: temporary, need change to get from key blocks. */
	return committee.Committeemembers
}

func (committee *Committee) GetPrivateSeqInCom(point kyber.Point) int {
	var seq int
	find := false

	log.Lvl1("pulblickey: ", point)
	for index, public := range committee.Committeemembers {
		log.Lvl1("index: ", index, " public:", public)
		if public.Equal(point) {
			seq = index
			find = true
			break
		}
	}

	if find == false {
		return -1
	}

	return seq
}

func (committee *Committee) GetCurrentLeaderSeq() int {
	return committee.CurrentLeaderSeq
}

func (committee *Committee) GetNextLeaderSeq() int {
	return committee.CurrentLeaderSeq + 1
}
