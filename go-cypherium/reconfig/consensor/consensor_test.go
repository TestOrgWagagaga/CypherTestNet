package consensor

import (
	"testing"

	"github.com/dedis/onet/app"

	"github.com/dedis/onet/log"
)

func TestMain(m *testing.M) {
	log.MainTest(m)
}

type TestCon struct {
	CurrentLeaderSeq int
	testCount        int
	consensus        *Consensus
	grouptoml        *app.GroupToml

	complete chan bool
}

func TestRootConsensus(t *testing.T) {
	log.SetDebugVisible(5)
	log.Lvl1("TestConsensus")

	testcon := &TestCon{}
	testcon.testCount = 0

	testcon.complete = make(chan bool)

	testcon.StartConsensus(true)
}

func TestSlaveConsensus(t *testing.T) {
	log.SetDebugVisible(5)
	log.Lvl1("TestConsensus")

	testcon := &TestCon{}
	testcon.testCount = 0

	testcon.complete = make(chan bool)

	testcon.StartConsensus(false)
}

func TestSlave2Consensus(t *testing.T) {
	log.SetDebugVisible(5)
	log.Lvl1("TestConsensus")

	testcon := &TestCon{}
	testcon.testCount = 0

	testcon.complete = make(chan bool)

	testcon.StartConsensus2(false)
}

func (testcon *TestCon) GetCothorityConfig(root bool) (error, *app.CothorityConfig) {
	//log.Lvl1(TomlFileName_Public)
	hc := &app.CothorityConfig{}
	//_, err := toml.DecodeFile(TomlFileName, hc)
	if root == true {
		//hc.Address = "tls://10.28.18.123:6879"
		hc.Address = "tls://192.168.1.103:6879"
		hc.Private = "3ac2810cff62e2c7bf937680f492dcc0e41ac9989e8024a3ceaae16de9633604"
		hc.Public = "9e3877e52b90bbfba0176aa10f7340bd4032573f3b1f6daf57e6c6b16045b2ec"
	} else {
		//hc.Address = "tls://10.28.18.123:7000"
		hc.Address = "tls://192.168.1.103:7000"
		hc.Private = "f57bb4e66bc80a20fd17f4d1efa45fae07d1b5b39e25d000bcc3cdf7ee3f7802"
		hc.Public = "0ee01af829befd3660a36ef5823743dd7465e5bd1829495b1cf909271fccf3ea"
	}

	hc.Suite = "Ed25519"
	log.Lvl1(hc.Address)
	log.Lvl1(hc.Private)
	log.Lvl1(hc.Public)
	log.Lvl1(hc.Suite)
	log.Lvl1(hc.ListenAddress)
	log.Lvl1(hc.WebSocketTLSCertificate)
	log.Lvl1(hc.WebSocketTLSCertificateKey)

	//if err != nil {
	//	return errors.New("DecodeFile Failed: " + err.Error()), nil, nil
	//}
	//og.Lvl1(hc.Public)

	//point, err := encoding.StringHexToPoint(cothority.Suite, hc.Public)
	//if err != nil {
	//	return errors.New("StringHexToPoint failed: " + err.Error()), nil
	//}
	return nil, hc
}

func (testcon *TestCon) StartConsensus2(root bool) {
	cothorityconfig := &app.CothorityConfig{}

	cothorityconfig.Address = "tls://192.168.1.103:7008"
	cothorityconfig.Private = "07ca6ba63fb03a6d93d15e7199747a2aa0514092bd79ad61a4ed27408f65a00e"
	cothorityconfig.Public = "364a1efc5d2dfb0be44bf1d95179a2af3b2a75535fa57e35417e511736661559"
	cothorityconfig.Suite = "Ed25519"
	log.Lvl1(cothorityconfig.Address)
	log.Lvl1(cothorityconfig.Private)
	log.Lvl1(cothorityconfig.Public)
	log.Lvl1(cothorityconfig.Suite)
	log.Lvl1(cothorityconfig.ListenAddress)
	log.Lvl1(cothorityconfig.WebSocketTLSCertificate)
	log.Lvl1(cothorityconfig.WebSocketTLSCertificateKey)

	//_, cothorityconfig := testcon.GetCothorityConfig(root)
	consensus, _ := NewConsensus(cothorityconfig)
	testcon.consensus = consensus
	testcon.testCount++
	testcon.consensus.Start()
	log.Info("<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<")
	if testcon.consensus.isRoot() {
		log.Info("leader0000000")
		testcon.consensus.txblockconsensus()
		//testcon.consensus.txblockconsensus()
		//testcon.consensus.txblockconsensus()
	}
	log.Info(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
	<-consensus.txblockdonechan

	log.Info(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>----")
	//testcon.consensus.viewChange()
	//<-testcon.consensus.viewdonechan
	if testcon.consensus.isRoot() {
		log.Info("leader111111")
		testcon.consensus.txblockconsensus()
	}
	<-consensus.txblockdonechan
	log.Info(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>=====")
	<-testcon.complete
	testcon.consensus.close()
}

func (testcon *TestCon) StartConsensus(root bool) {
	servier1 := &app.ServerToml{
		Address:     "tls://192.168.1.103:7008",
		Suite:       "Ed25519",
		Public:      "364a1efc5d2dfb0be44bf1d95179a2af3b2a75535fa57e35417e511736661559",
		Description: "member2",
	}
	_, cothorityconfig := testcon.GetCothorityConfig(root)
	consensus, _ := NewConsensus(cothorityconfig)
	testcon.consensus = consensus
	testcon.testCount++
	testcon.consensus.Start()
	log.Info("<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<")
	if testcon.consensus.isRoot() {
		log.Info("leader0000000")
		testcon.consensus.txblockconsensus()
		//testcon.consensus.txblockconsensus()
		//testcon.consensus.txblockconsensus()
	}
	log.Info(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
	<-consensus.txblockdonechan

	log.Info(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>----")
	//testcon.consensus.viewChange()
	//<-testcon.consensus.viewdonechan
	if testcon.consensus.isRoot() {
		log.Info("leader111111")
		testcon.consensus.txblockconsensus()
	}
	<-consensus.txblockdonechan
	//servier1 := &app.ServerToml{"tls://192.168.1.103:6879", "Ed25519", "9e3877e52b90bbfba0176aa10f7340bd4032573f3b1f6daf57e6c6b16045b2ec", "leader"}
	//servier2 := &app.ServerToml{"tls://192.168.1.103:7000", "Ed25519", "0ee01af829befd3660a36ef5823743dd7465e5bd1829495b1cf909271fccf3ea", "slave"}
	testcon.consensus.memberchange(servier1)
	log.Info(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>...")
	<-consensus.reconfigdonechan

	if testcon.consensus.isRoot() {
		log.Info("leader2222222")
		testcon.consensus.txblockconsensus()
	}
	log.Info(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>=====")
	<-testcon.complete
	testcon.consensus.close()
}
