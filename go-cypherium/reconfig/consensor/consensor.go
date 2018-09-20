package consensor

import (
	"errors"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/cypherium_private/go-cypherium/core"
	"github.com/cypherium_private/go-cypherium/core/state"
	"github.com/cypherium_private/go-cypherium/core/types"
	"github.com/cypherium_private/go-cypherium/reconfig/bftcosi"
	"github.com/cypherium_private/go-cypherium/reconfig/committee"
	"github.com/cypherium_private/go-cypherium/reconfig/events"
	"github.com/cypherium_private/go-cypherium/rlp"

	"github.com/dedis/cothority"
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/util/encoding"
	"github.com/dedis/onet"
	"github.com/dedis/onet/app"
	"github.com/dedis/onet/log"
)

/*
func init() {
	for _, i := range []interface{}{
		ViewChangeSync{},
	} {
		network.RegisterMessage(i)
	}
}
*/

type ViewChangeSync struct {
	view int
}

const (
	ServiceName      = "bftservice"
	TestProtocolName = "DummyBFTCoSi"
)

// Service is our template-service
type Service struct {
	// We need to embed the ServiceProcessor, so that incoming messages
	// are correctly handled.
	*onet.ServiceProcessor
}

type Consensus_TxBlock struct {
	/* Fill the field. */
	leader       int
	TxBlockBytes []byte
}

type Consensus_Done struct {
	//done chan bool
	leader int
}

type viewChangeConfirm struct {
	seq int
}

type viewChangeSync struct {
	seq int
}

type KeyBlock struct {
	// filled it
}

type committeeChange struct {
	servertoml *app.ServerToml
}

type txBlockEvent Consensus_TxBlock
type txDoneEvent Consensus_Done
type viewChangedEvent viewChangeConfirm
type KeyBlockEvent KeyBlock
type committeeChangeEvent committeeChange

type Consensus struct {
	Bftservice      *Service
	Bftprotocol     *bftcosi.ProtocolBFTCoSi
	Server          *onet.Server
	tree            *onet.Tree
	group           *app.Group
	cothorityconfig *app.CothorityConfig

	committee *committee.Committee

	public kyber.Point

	view int

	Viewdonechan     chan bool
	reconfigdonechan chan bool

	Txblockdonechan chan bool

	manager events.Manager

	root bool

	ConsensusDone     chan bool
	ViewChangeConfirm chan bool
	TestConut         chan bool

	closing      bool
	closingMutex sync.Mutex
	txblockchain *core.BlockChain
}

var cMux sync.Mutex

func NewConsensus(privatefile string, publicsfile string, txblockchain *core.BlockChain) (*Consensus, error) {
	log.Lvl5("NewConsensus")

	consensus := &Consensus{
		ConsensusDone:     make(chan bool),
		ViewChangeConfirm: make(chan bool),
		view:              0,
		Viewdonechan:      make(chan bool),
		Txblockdonechan:   make(chan bool),
		reconfigdonechan:  make(chan bool),
		txblockchain:      txblockchain,
	}

	_, consensus.cothorityconfig = consensus.GetCothorityConfig(privatefile)
	consensus.public, _ = encoding.StringHexToPoint(cothority.Suite, consensus.cothorityconfig.Public)
	consensus.committee, _ = committee.NewCommittee(publicsfile)
	consensus.group = consensus.committee.Group
	consensus.manager = events.NewManagerImpl()
	consensus.manager.SetReceiver(consensus)
	consensus.manager.Start()

	return consensus, nil
}

func (consensus *Consensus) GetCothorityConfig(file string) (error, *app.CothorityConfig) {
	//log.Lvl1(TomlFileName_Public)
	hc := &app.CothorityConfig{}
	toml.DecodeFile(file, hc)
	/*
		hc.Address = "tls://10.28.18.123:6879"
		hc.Private = "3ac2810cff62e2c7bf937680f492dcc0e41ac9989e8024a3ceaae16de9633604"
		hc.Public = "9e3877e52b90bbfba0176aa10f7340bd4032573f3b1f6daf57e6c6b16045b2ec"

		hc.Address = "tls://10.28.18.123:7000"
		hc.Private = "f57bb4e66bc80a20fd17f4d1efa45fae07d1b5b39e25d000bcc3cdf7ee3f7802"
		hc.Public = "0ee01af829befd3660a36ef5823743dd7465e5bd1829495b1cf909271fccf3ea"

		hc.Suite = "Ed25519"
	*/
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

func (consensus *Consensus) Txblockconsensus(msg []byte) {
	log.Lvl1(" txblockconsensus")
	consensus.manager.Queue() <- txBlockEvent{TxBlockBytes: msg}
}

func (consensus *Consensus) txblockdone() {
	log.Lvl5("txblockdone!!!!!!!")
	if consensus.isRoot() {
		consensus.ConsensusDone <- true
	}
	log.Lvl5("txblockdone222!!!!!!!")
	consensus.manager.Queue() <- txDoneEvent{}
}

func (consensus *Consensus) viewChange() {
	log.Lvl1("viewChange")
	consensus.manager.Queue() <- viewChangedEvent{}
}

func (consensus *Consensus) keyblock() {
	consensus.manager.Queue() <- KeyBlockEvent{}
}

func (consensus *Consensus) memberchange(server_toml *app.ServerToml) {
	log.Lvl1("memberchange")
	consensus.manager.Queue() <- committeeChangeEvent{servertoml: server_toml}
}

func (consensus *Consensus) HandleViewchange() error {
	log.Lvl5("HandleViewchange")
	consensus.view++

	consensus.committee.CurrentLeaderSeq = consensus.view

	if consensus.isRoot() {
		log.Lvl1(" I am consensus root node")
		//consensus.Server.ClosChannel()
		consensus.Bftservice = consensus.Server.Service(ServiceName).(*Service)
		list_len := len(consensus.group.Roster.List) - 1
		consensus.tree = consensus.group.Roster.GenerateNaryTreeWithRoot(list_len,
			consensus.Bftservice.ServerIdentity())
	}

	//consensus.Start()

	// release close
	consensus.closingMutex.Lock()
	consensus.closing = false
	consensus.closingMutex.Unlock()
	return nil
}

func (consensus *Consensus) reconfig() error {
	log.Lvl5("reconfig")

	if consensus.isRoot() {
		log.Lvl1(" I am consensus root node")
		//consensus.Server.ClosChannel()
		consensus.Bftservice = consensus.Server.Service(ServiceName).(*Service)
		list_len := len(consensus.group.Roster.List) - 1
		consensus.tree = consensus.group.Roster.GenerateNaryTreeWithRoot(list_len,
			consensus.Bftservice.ServerIdentity())
	}

	// release close
	consensus.closingMutex.Lock()
	consensus.closing = false
	consensus.closingMutex.Unlock()
	return nil
}

func (consensus *Consensus) ProcessEvent(event events.Event) events.Event {
	log.Lvl5("Consensus ProcessEvent")
	switch et := event.(type) {
	case txBlockEvent:
		log.Lvl5("Consensus txBlock")
		txBlock := et
		return consensus.TxblockHandle(txBlock)
	case KeyBlockEvent:
		//keyBlock := et
		//return consensus.TxblockHandle(txBlock)
		return nil
	case txDoneEvent:
		//txDone := et
		//consens done, implement write block
		consensus.Txblockdonechan <- true
		log.Lvl1("Verification succeed!!!!!!!!!!!!")
		return nil
	case viewChangedEvent:
		log.Lvl1("handle viewchage!!!!!!!!!!!!")
		consensus.Close()
		//consensus.Server.Close()
		log.Lvl1("handle viewchage   step 2!!!!!!!!!!!!")
		consensus.HandleViewchange()
		log.Lvl1("handle viewchage   step 3!!!!!!!!!!!!")
		consensus.Viewdonechan <- true
		return nil
	case committeeChangeEvent:
		log.Lvl1("committee change start!!!!!!!!!!!!")
		consensus.Close()
		commChEvent := et

		point, _ := encoding.StringHexToPoint(cothority.Suite, commChEvent.servertoml.Public)
		if consensus.public.Equal(point) {
			log.Lvl1("adding myself!!!!!!!!!!!!")
			return nil
		}

		_, consensus.group = consensus.committee.ReconfigCommitteeMembers(commChEvent.servertoml)
		consensus.reconfig()
		consensus.reconfigdonechan <- true
		log.Lvl1("committee change succeed!!!!!!!!!!!!")
		return nil
	default:
		return nil
	}
}

func (consensus *Consensus) Close() {
	log.Lvl5("Consensus close")
	//consensus.manager.Halt()
	consensus.setClosing()
	//consensus.Server.Close()
}

func newService(c *onet.Context) (onet.Service, error) {
	service := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),
	}
	return service, nil
}

func (consensus *Consensus) Start() {
	var err error

	// Register test protocol using BFTCoSi
	onet.GlobalProtocolRegister(TestProtocolName,
		func(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {

			bft, err := bftcosi.NewBFTCoSiProtocol(n, consensus.txblockdone, consensus.viewChange, consensus.verify)
			bft.RegisterWriteBlock(consensus.txblockchain.BftcosiWriteBlock)
			return bft, err
		})

	onet.RegisterNewService(ServiceName, newService)

	//LocalSeq, _ := consensus.committee.GetPrivateSeqInCom(consensus.public)
	//colx_name := fmt.Sprintf("co%d/private.toml", LocalSeq)
	//log.Lvl1(colx_name)
	//_, consensus.Server, err = app.ParseCothority(colx_name)
	consensus.Server, err = app.ParseCothority_cyher(consensus.cothorityconfig)
	if err != nil {
		log.Fatal("Couldn't parse config:", err)
	}

	log.Lvl1(" Consensus server Start")
	consensus.Server.Start()
	log.Lvl1(" Consensus server end")

	if consensus.isRoot() {
		log.Lvl1(" I am consensus root node")
		consensus.Bftservice = consensus.Server.Service(ServiceName).(*Service)
		list_len := len(consensus.group.Roster.List) - 1
		consensus.tree = consensus.group.Roster.GenerateNaryTreeWithRoot(list_len,
			consensus.Bftservice.ServerIdentity())
	}

	log.Lvl1("Start end")
}

func (consensus *Consensus) isRoot() bool {
	public := consensus.cothorityconfig.Public
	point, err := encoding.StringHexToPoint(cothority.Suite, public)
	if err != nil {
		panic("StringHexToPoint failed")
	}
	localseq := consensus.committee.GetPrivateSeqInCom(point)
	if localseq < 0 {
		panic("StringHexToPoint failed")
	}

	return localseq == consensus.committee.GetCurrentLeaderSeq()
}

func (consensus *Consensus) isClosing() bool {
	consensus.closingMutex.Lock()
	defer consensus.closingMutex.Unlock()
	return consensus.closing
}

func (consensus *Consensus) setClosing() {
	consensus.closingMutex.Lock()
	consensus.closing = true
	consensus.closingMutex.Unlock()
}

func (consensus *Consensus) TxblockHandle(txblock txBlockEvent) error {
	var root *bftcosi.ProtocolBFTCoSi
	if consensus.isClosing() {
		log.Lvl1("TxblockHandle isClosing")
		return errors.New("Closing and ")
	}

	if !consensus.isRoot() {
		panic("consensus must be start by root")
	}

	//1. only for  test.
	//txblock.TxBlockBytes = []byte("Hello BFTCoSi")

	//2. create and run the bft protocol
	pi, err :=
		consensus.Bftservice.CreateProtocol(TestProtocolName, consensus.tree)
	if err != nil {
		log.Lvl1("CreateProtocol failed!")
	}

	//msg := []byte("Hello BFTCoSi")
	root = pi.(*bftcosi.ProtocolBFTCoSi)
	root.Msg = txblock.TxBlockBytes
	root.Data = []byte("163")

	go root.Start()
	wait := time.Second * 60
	select {
	case <-consensus.ConsensusDone:
		log.Lvl1("%s: Verification succeed", root.Name())

	case <-time.After(wait):
		log.Lvl1("Going to break because of timeout")
		log.Lvl1("Waited " + wait.String() + " for BFTCoSi to finish ...")
	}
	log.Lvl1("TxblockHandle endddddd")
	return nil
}

// verify function that returns true if the txblock is ok.
func (consensus *Consensus) verify(m []byte, d []byte) (*types.Block, types.Receipts, *state.StateDB, []*types.Log, bool) {

	block := new(types.Block)
	rlp.DecodeBytes(m, block)

	var (
		receipts types.Receipts
		state    *state.StateDB
		logs     []*types.Log
		err      error
	)
	// if block.NumberU64()%100 == 0 {
	// 	return nil, nil, nil, nil, false
	// }
	if receipts, state, logs, err = consensus.txblockchain.Bftverifyblock(block); err != nil {
		return nil, nil, nil, nil, false
	}

	// miner.TmpMiner.receipts = receipts
	// miner.TmpMiner.state = state
	// miner.TmpMiner.logs = logs

	return block, receipts, state, logs, true
}
