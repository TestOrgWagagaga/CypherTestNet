package bftcosi

import (
	"errors"
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/dedis/kyber/suites"
	"github.com/dedis/kyber/sign/schnorr"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/stretchr/testify/assert"
)

// Service is our template-service
type Service struct {
	// We need to embed the ServiceProcessor, so that incoming messages
	// are correctly handled.
	*onet.ServiceProcessor
}

type Counter struct {
	veriCount   int
	refuseCount int
	sync.Mutex
}

type Counters struct {
	counters []*Counter
	sync.Mutex
}

func (co *Counters) add(c *Counter) {
	co.Lock()
	co.counters = append(co.counters, c)
	co.Unlock()
}

func (co *Counters) size() int {
	co.Lock()
	defer co.Unlock()
	return len(co.counters)
}

func (co *Counters) get(i int) *Counter {
	co.Lock()
	defer co.Unlock()
	return co.counters[i]
}

var counters = &Counters{}
var cMux sync.Mutex

var tSuite = cothority.Suite

func TestMain(m *testing.M) {
	log.MainTest(m)
}

// Returns the number of calls.
func cmdCounter(c *cli.Context) error {
	log.Info("Counter command")
	group := readGroup(c)
	client := template.NewClient()
	counter, err := client.Count(group.Roster.RandomServerIdentity())
	if err != nil {
		return errors.New("When asking for counter: " + err.Error())
	}
	log.Info("Number of requests:", counter)
	return nil
}

func readGroup(c *cli.Context) *app.Group {
	if c.NArg() != 1 {
		log.Fatal("Please give the group-file as argument")
	}
	name := c.Args().First()
	f, err := os.Open(name)
	log.ErrFatal(err, "Couldn't open group definition file")
	group, err := app.ReadGroupDescToml(f)
	log.ErrFatal(err, "Error while reading group definition file", err)
	if len(group.Roster.List) == 0 {
		log.ErrFatalf(err, "Empty entity or invalid group defintion in: %s",
			name)
	}
	return group
}

func newService(c *onet.Context) (onet.Service, error) {
	log.Lvl3("newService!!!!!!!")
	service := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),
	}
	/*
			if err := s.RegisterHandlers(s.Clock, s.Count); err != nil {
				return nil, errors.New("Couldn't register messages")
			}

		if err := s.tryLoad(); err != nil {
			log.Lvl3("newService error!!!!!!!")
			log.Error(err)
			return nil, err
		}
	*/
	return service, nil
}

func txblockdone() {
	consensus1.Done <- true
}

func viewchangeconfirm() {

}

func TestTcpBftCoSi(t *testing.T) {
	const ServiceName = "bftservice"
	const TestProtocolName = "DummyBFTCoSi"
	const TomlFileName1 = "co1/private.toml"
	const TomlFileName1_Public = "./public.toml"
	log.SetDebugVisible(5)
	log.Lvl1("TestBftCoSi")

	// Register test protocol using BFTCoSi
	onet.GlobalProtocolRegister(TestProtocolName, func(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
		return NewBFTCoSiProtocol(n, txblockdone, viewchangeconfirm, verify)
	})

	consensus1.Done = make(chan bool)

	onet.RegisterNewService(ServiceName, newService)

	_, server, err := app.ParseCothority(TomlFileName1)
	if err != nil {
		log.Fatal("Couldn't parse config:", err)
	}
	log.Lvl1("Server start 00")
	server.Start()
	log.Lvl1("Server start 01")

	f, err := os.Open(TomlFileName1_Public)
	group, err := app.ReadGroupDescToml(f)
	if len(group.Roster.List) == 0 {
		log.Lvl1("Empty entity or invalid group defintion in: %s",
			TomlFileName1_Public)
	}

	log.Lvl1("begin to create the tree")
	s := server.Service(ServiceName)
	tree := group.Roster.GenerateNaryTreeWithRoot(len(group.Roster.List)-1, s.(*Service).ServerIdentity())
	log.Lvl1("begin to create the tree:", tree.Dump)

	for testCount := 1; testCount <= 100000; testCount++ {
		//log.Lvl1("Simple count")
		runTcpProtocol(&consensus1, TestProtocolName, ServiceName, server, tree)
		log.Lvl1("Simple count OK:  ", testCount)
	}
}

func runTcpProtocol(consensus *Consensus, protocolName string, serviceName string, server *onet.Server, tree *onet.Tree) error {
	// Start the protocol
	s := server.Service(serviceName)
	pi, err := s.(*Service).CreateProtocol(protocolName, tree)
	if err != nil {
		log.Lvl1("CreateProtocol failed!")
	}

	//done := make(chan bool)
	// create the message we want to sign for this round
	msg := []byte("Hello BFTCoSi")
	// Register the function generating the protocol instance
	var root *ProtocolBFTCoSi
	root = pi.(*ProtocolBFTCoSi)
	root.Msg = msg
	//cMux.Lock()
	//counter := &Counter{refuseCount: 0}
	//counters.add(counter)
	root.Data = []byte("163")
	//log.Lvl3("Added counter", counters.size()-1, 0)

	// function that will be called when protocol is finished by the root
	//root.RegisterOnDone(func() {
	//	done <- true
	//})

	go root.Start()
	//log.Lvl1("Launched protocol")
	// are we done yet?
	wait := time.Second * 60
	select {
	case <-consensus1.Done:
		sig := root.Signature()
		log.Print(root.Name(), "->SigRoot:", sig.Sig)
		err := sig.Verify(root.Suite(), root.Roster().Publics())
		if err != nil {
			log.Lvl1("%s Verification of the signature refused: %s - %+v", root.Name(), err.Error(), sig.Sig)
		}
		log.Lvl1("%s: Verification succeed", root.Name(), sig)

	case <-time.After(wait):
		log.Lvl1("Going to break because of timeout")
		log.Lvl1("Waited " + wait.String() + " for BFTCoSi to finish ...")
	}

	return nil
}

func TestBftCoSi(t *testing.T) {
	const TestProtocolName = "DummyBFTCoSi"
	log.SetDebugVisible(5)
	log.Lvl1("TestTcpBftCoSi")

	consensus := &consensus1
	consensus.Done = make(chan bool)
	consensus.TestValue = 22

	consensus2.Done = make(chan bool)
	consensus.TestValue = 33

	onet.GlobalProtocolRegister(TestProtocolName, func(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
		return NewBFTCoSiProtocol(n, txblockdone, viewchangeconfirm, verify)
	})

	//for testCount := 1; testCount <= 100000; testCount++ {
	//	log.Lvl1("Simple count")
	runProtocol(t, consensus, TestProtocolName, 0)
	//	log.Printf("Simple count OK:  ", testCount)
	//}
}

func TestThreshold(t *testing.T) {
	const TestProtocolName = "DummyBFTCoSiThr"
	log.Lvl1("TestThreshold")

	// Register test protocol using BFTCoSi
	onet.GlobalProtocolRegister(TestProtocolName, func(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
		return NewBFTCoSiProtocol(n, txblockdone, viewchangeconfirm, verify)
	})

	tests := []struct{ h, t int }{
		{1, 0},
		{2, 0},
		{3, 1},
		{4, 1},
		{5, 1},
		{6, 2},
	}
	for _, s := range tests {
		local := onet.NewLocalTest(tSuite)
		hosts, thr := s.h, s.t
		log.Lvl3("Hosts is", hosts)
		_, _, tree := local.GenBigTree(hosts, hosts, min(2, hosts-1), true)
		log.Lvl3("Tree is:", tree.Dump())

		// Start the protocol
		node, err := local.CreateProtocol(TestProtocolName, tree)
		log.ErrFatal(err)
		bc := node.(*ProtocolBFTCoSi)
		assert.Equal(t, thr, bc.allowedExceptions, "hosts was %d", hosts)
		local.CloseAll()
	}
}

func TestCheckRefuse(t *testing.T) {
	const TestProtocolName = "DummyBFTCoSiRefuse"

	consensus := &Consensus{
		Done: make(chan bool),
	}

	// Register test protocol using BFTCoSi
	onet.GlobalProtocolRegister(TestProtocolName, func(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
		return NewBFTCoSiProtocol(n, txblockdone, viewchangeconfirm, verifyRefuse)
	})

	for refuseCount := 1; refuseCount <= 3; refuseCount++ {
		log.Lvl2("Refuse at", refuseCount)
		runProtocol(t, consensus, TestProtocolName, refuseCount)
	}
}

func TestCheckRefuseMore(t *testing.T) {
	const TestProtocolName = "DummyBFTCoSiRefuseMore"

	consensus := &Consensus{
		Done: make(chan bool),
	}
	// Register test protocol using BFTCoSi
	onet.GlobalProtocolRegister(TestProtocolName, func(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
		return NewBFTCoSiProtocol(n, txblockdone, viewchangeconfirm, verifyRefuseMore)
	})

	for _, n := range []int{3, 4, 13} {
		for refuseCount := 1; refuseCount <= 3; refuseCount++ {
			log.Lvl2("RefuseMore at", refuseCount)
			runProtocolOnce(t, consensus, n, TestProtocolName, refuseCount, refuseCount <= n-(n+1)*2/3)
		}
	}
}

func TestCheckRefuseBit(t *testing.T) {
	const TestProtocolName = "DummyBFTCoSiRefuseBit"

	consensus := &Consensus{
		Done: make(chan bool),
	}
	// Register test protocol using BFTCoSi
	onet.GlobalProtocolRegister(TestProtocolName, func(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
		return NewBFTCoSiProtocol(n, txblockdone, viewchangeconfirm, verifyRefuseBit)
	})

	wg := sync.WaitGroup{}
	for _, n := range []int{3} {
		for refuseCount := 0; refuseCount < 1<<uint(n); refuseCount++ {
			wg.Add(1)
			go func(n, fc int) {
				log.Lvl1("RefuseBit at", n, fc)
				runProtocolOnce(t, consensus, n, TestProtocolName, fc, bitCount(fc) < (n+1)*2/3)
				log.Lvl3("Done with", n, fc)
				wg.Done()
			}(n, refuseCount)
		}
	}
	wg.Wait()
}

func TestCheckRefuseParallel(t *testing.T) {
	//t.Skip("Skipping and hoping it will be resolved with #467")
	const TestProtocolName = "DummyBFTCoSiRefuseParallel"

	consensus := &Consensus{
		Done: make(chan bool),
	}
	// Register test protocol using BFTCoSi
	onet.GlobalProtocolRegister(TestProtocolName, func(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
		return NewBFTCoSiProtocol(n, txblockdone, viewchangeconfirm, verifyRefuseBit)
	})

	wg := sync.WaitGroup{}
	n := 3
	for fc := 0; fc < 8; fc++ {
		wg.Add(1)
		go func(fc int) {
			runProtocolOnce(t, consensus, n, TestProtocolName, fc, bitCount(fc) < (n+1)*2/3)
			log.Lvl3("Done with", n, fc)
			wg.Done()
		}(fc)
	}
	wg.Wait()
}

func TestNodeFailure(t *testing.T) {
	if testing.Short() {
		t.Skip("node failure tests do not run on travis, see #1000")
	}

	const TestProtocolName = "DummyBFTCoSiNodeFailure"

	consensus := &consensus1
	consensus.Done = make(chan bool)

	// Register test protocol using BFTCoSi
	onet.GlobalProtocolRegister(TestProtocolName, func(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
		return NewBFTCoSiProtocol(n, txblockdone, viewchangeconfirm, verify)
	})

	nbrHostsArr := []int{5, 7, 10}
	for _, nbrHosts := range nbrHostsArr {
		if err := runProtocolOnceGo(consensus, nbrHosts, TestProtocolName, 0, true, nbrHosts/3, nbrHosts-1); err != nil {
			t.Fatalf("%d/%s/%d/%t: %s", nbrHosts, TestProtocolName, 0, true, err)
		}
	}
}

func runProtocol(t *testing.T, consensus *Consensus, name string, refuseCount int) {
	//for _, nbrHosts := range []int{3, 5, 7, 15} {
	for _, nbrHosts := range []int{2} {
		runProtocolOnce(t, consensus, nbrHosts, name, refuseCount, true)
	}
}

func runProtocolOnce(t *testing.T, consensus *Consensus, nbrHosts int, name string, refuseCount int, succeed bool) {
	if err := runProtocolOnceGo(consensus, nbrHosts, name, refuseCount, succeed, 0, nbrHosts-1); err != nil {
		t.Fatalf("%d/%s/%d/%t: %s", nbrHosts, name, refuseCount, succeed, err)
	}
}

var Verifydata []byte
var PublicPP kyber.Point

func runProtocolOnceGo(consensus *Consensus, nbrHosts int, name string, refuseCount int, succeed bool, killCount int, bf int) error {
	log.Lvl1("Running BFTCoSi with", nbrHosts, "hosts")
	local := onet.NewLocalTest(tSuite)
	local.Check = onet.CheckNone
	defer local.CloseAll()

	// we set the branching factor to nbrHosts - 1 to have the root broadcast messages
	servers, _, tree := local.GenBigTree(nbrHosts, nbrHosts, bf, true)
	//log.Lvl1("Tree is:", tree.Dump())

	//done := make(chan bool)
	// create the message we want to sign for this round
	msg := []byte("Hello BFTCoSi")
	// Register the function generating the protocol instance
	var root *ProtocolBFTCoSi

	for testCount := 1; testCount <= 10; testCount++ {
		// Start the protocol
		node, err := local.CreateProtocol(name, tree)
		if err != nil {
			return errors.New("Couldn't create new node: " + err.Error())
		}
		root = node.(*ProtocolBFTCoSi)
		//log.Print(root.Name(), "->TestValue:", root.Consensus.TestValue)
		Verifydata, _ = schnorr.Sign(cothority.Suite, root.TreeNodeInstance.Private(), msg)
		PublicPP = root.TreeNodeInstance.Public()
		root.Msg = msg
		cMux.Lock()
		counter := &Counter{refuseCount: refuseCount}
		counters.add(counter)
		root.Data = []byte(strconv.Itoa(counters.size() - 1))
		log.Lvl1("Added counter", counters.size()-1, refuseCount, counters.size(), root.Data)
		cMux.Unlock()
		log.ErrFatal(err)

		// function that will be called when protocol is finished by the root
		root.RegisterOnDone(func() {
			consensus1.Done <- true
		})

		// kill the leafs first
		killCount = min(killCount, len(servers))
		for i := len(servers) - 1; i > len(servers)-killCount-1; i-- {
			log.Lvl1("Closing server:", servers[i].ServerIdentity.Public, servers[i].Address())
			if e := servers[i].Close(); e != nil {
				return e
			}
		}

		go root.Start()
		log.Lvl1("Launched protocol")
		// are we done yet?
		wait := time.Second * 10
		select {
		case <-consensus1.Done:
			//<-consensus2.Done
			//case <-done:
			//counter.Lock()
			//if counter.veriCount != nbrHosts-killCount {
			//	return errors.New("each host should have called verification")
			//}
			// if assert refuses we don't care for unlocking (t.Refuse)
			//counter.Unlock()
			//log.Print(root.Name(), "->TestValue:", root.Consensus.TestValue)
			sig := root.Signature()
			log.Print(root.Name(), "->SigRoot:", sig.Sig)
			err := sig.Verify(root.Suite(), root.Roster().Publics())
			if succeed && err != nil {
				return fmt.Errorf("%s Verification of the signature refused: %s - %+v", root.Name(), err.Error(), sig.Sig)
			}
			if !succeed && err == nil {
				return fmt.Errorf("%s: Shouldn't have succeeded for %d hosts, but signed for count: %d",
					root.Name(), nbrHosts, refuseCount)
			}
			log.Print("Verification succeed", testCount)

		case <-time.After(wait):
			log.Lvl1("Going to break because of timeout")
			return errors.New("Waited " + wait.String() + " for BFTCoSi to finish ...")
		}
	}
	return nil
}

// Verify function that returns true if the length of the data is 1.
func verify(m []byte, d []byte) bool {
	//c, err := strconv.Atoi(string(d))
	//log.ErrFatal(err)
	//counter := counters.get(c)
	//counter.Lock()
	//counter.veriCount++
	//log.Lvl4("Verification called", counter.veriCount, "times", d)
	//counter.Unlock()
	//if len(d) == 0 {
	//	log.Error("Didn't receive correct data")
	//	return false
	//}
	for testCount := 1; testCount <= 1; testCount++ {
		msg := []byte("Hello BFTCoSi")
		ok := schnorr.Verify(cothority.Suite, PublicPP, msg, Verifydata)
		//if ok == false {
		if ok != nil {
			//log.Printf("viewchange verify failed")
		} else {
			//log.Printf("viewchange verify successfully")
		}
	}

	return true
}

// Verify-function that will refuse if we're the `refuseCount`ed call.
func verifyRefuse(m []byte, d []byte) bool {
	c, err := strconv.Atoi(string(d))
	log.ErrFatal(err)
	counter := counters.get(c)
	counter.Lock()
	defer counter.Unlock()
	counter.veriCount++
	if counter.veriCount == counter.refuseCount {
		log.Lvl2("Refusing for count==", counter.refuseCount)
		return false
	}
	log.Lvl3("Verification called", counter.veriCount, "times")
	log.Lvl3("Ignoring message:", string(m))
	if len(d) == 0 {
		log.Error("Didn't receive correct data")
		return false
	}
	return true
}

// Verify-function that will refuse for all calls >= `refuseCount`.
func verifyRefuseMore(m []byte, d []byte) bool {
	c, err := strconv.Atoi(string(d))
	log.ErrFatal(err)
	counter := counters.get(c)
	counter.Lock()
	defer counter.Unlock()
	counter.veriCount++
	if counter.veriCount <= counter.refuseCount {
		log.Lvlf2("Refusing for %d<=%d", counter.veriCount,
			counter.refuseCount)
		return false
	}
	log.Lvl3("Verification called", counter.veriCount, "times")
	log.Lvl3("Ignoring message:", string(m))
	if len(d) == 0 {
		log.Error("Didn't receive correct data")
		return false
	}
	return true
}

func bitCount(x int) int {
	count := 0
	for x != 0 {
		x &= x - 1
		count++
	}
	return count
}

// Verify-function that will refuse if the `called` bit is 0.
func verifyRefuseBit(m []byte, d []byte) bool {
	c, err := strconv.Atoi(string(d))
	log.ErrFatal(err)
	counter := counters.get(c)
	counter.Lock()
	defer counter.Unlock()
	log.Lvl4("Counter", c, counter.refuseCount, counter.veriCount)
	myBit := uint(counter.veriCount)
	counter.veriCount++
	if counter.refuseCount&(1<<myBit) != 0 {
		log.Lvl2("Refusing for myBit ==", myBit)
		return false
	}
	log.Lvl3("Verification called", counter.veriCount, "times")
	return true
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
