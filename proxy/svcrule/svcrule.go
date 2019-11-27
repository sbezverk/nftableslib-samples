package main

import (
	"fmt"
	"os"

	"github.com/google/nftables"
	"github.com/sbezverk/nftableslib"
	"golang.org/x/sys/unix"
)

func setActionVerdict(key int, chain ...string) *nftableslib.RuleAction {
	ra, err := nftableslib.SetVerdict(key, chain...)
	if err != nil {
		fmt.Printf("failed to SetVerdict with error: %+v\n", err)
	}
	return ra
}

func setIPAddr(addr string) *nftableslib.IPAddr {
	a, err := nftableslib.NewIPAddr(addr)
	if err != nil {
		fmt.Printf("error %+v return from NewIPAddr for address: %s\n", err, addr)
	}
	return a
}

func main() {
	// Initializing netlink connection
	conn := nftableslib.InitConn()
	ti := nftableslib.InitNFTables(conn)
	//	fmt.Printf("Cleaning nftable...\n")
	conn.FlushRuleset()

	if err := ti.Tables().CreateImm("ipv4table", nftables.TableFamilyIPv4); err != nil {
		fmt.Printf("Failed to create table ipv4table with error: %+v\n", err)
		os.Exit(1)
	}

	ci, err := ti.Tables().Table("ipv4table", nftables.TableFamilyIPv4)
	if err != nil {
		fmt.Printf("Failed to get chains interface for table ipv4table with error: %+v\n", err)
		os.Exit(1)
	}

	ch1Attr := nftableslib.ChainAttributes{
		Type:     nftables.ChainTypeNAT,
		Priority: 0,
		Hook:     nftables.ChainHookPrerouting,
		Policy:   nftableslib.ChainPolicyAccept,
	}

	if err := ci.Chains().CreateImm("ipv4chain-1", &ch1Attr); err != nil {
		fmt.Printf("Failed to chain  ipv4chain-1 for table ipv4table with error: %+v\n", err)
		os.Exit(1)
	}

	if err := ci.Chains().CreateImm("ipv4chain-2", nil); err != nil {
		fmt.Printf("Failed to chain  ipv4chain-2 for table ipv4table with error: %+v\n", err)
		os.Exit(1)
	}
	if err := ci.Chains().CreateImm("KUBE-MARK-MASQ", nil); err != nil {
		fmt.Printf("Failed to chain  KUBE-MARK-MASQ for table ipv4table with error: %+v\n", err)
		os.Exit(1)
	}

	c2ri, err := ci.Chains().Chain("ipv4chain-2")
	if err != nil {
		fmt.Printf("Failed to get rules interface for chain ipv4chain-2 with error: %+v\n", err)
		os.Exit(1)
	}

	svcRule := nftableslib.Rule{
		L3: &nftableslib.L3Rule{
			Src: &nftableslib.IPAddrSpec{
				List:  []*nftableslib.IPAddr{setIPAddr("57.112.0.0/12"), setIPAddr("157.113.0.0/12")},
				RelOp: nftableslib.NEQ,
			},
			Dst: &nftableslib.IPAddrSpec{
				List: []*nftableslib.IPAddr{setIPAddr("57.133.112.148")},
			},
		},
		L4: &nftableslib.L4Rule{
			L4Proto: unix.IPPROTO_TCP,
			Dst: &nftableslib.Port{
				List: nftableslib.SetPortList([]int{15004, 15008}),
			},
		},
		Action: setActionVerdict(unix.NFT_JUMP, "KUBE-MARK-MASQ"),
	}

	h1, err := c2ri.Rules().CreateImm(&svcRule)
	if err != nil {
		fmt.Printf("failed to create rule with error: %+v, exiting...\n", err)
		os.Exit(1)
	}

	fmt.Printf("Rule 1 handle: %d\n", h1)
}
