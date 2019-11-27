package main

import (
	"fmt"
	"os"

	"github.com/google/nftables"
	"github.com/sbezverk/nftableslib"
)

// The following code attempts to mimic in nftables the following iptables rule for chain Filter
// *filter
// -A INPUT -m conntrack --ctstate NEW -m comment --comment "kubernetes service portals" -j KUBE-SERVICES
// -A INPUT -m conntrack --ctstate NEW -m comment --comment "kubernetes externally-visible service portals" -j KUBE-EXTERNAL-SERVICES
// -A INPUT -j KUBE-FIREWALL

// -A FORWARD -m comment --comment "kubernetes forwarding rules" -j KUBE-FORWARD
// -A FORWARD -m conntrack --ctstate NEW -m comment --comment "kubernetes service portals" -j KUBE-SERVICES

// -A OUTPUT -m conntrack --ctstate NEW -m comment --comment "kubernetes service portals" -j KUBE-SERVICES
// -A OUTPUT -j KUBE-FIREWALL

// -A KUBE-EXTERNAL-SERVICES -d 192.168.80.104/32 -p tcp -m comment --comment "default/portal:portal has no endpoints" -m tcp --dport 8989 -j REJECT --reject-with icmp-port-unreachable

// -A KUBE-FIREWALL -m comment --comment "kubernetes firewall for dropping marked packets" -m mark --mark 0x8000/0x8000 -j DROP

// -A KUBE-FORWARD -m conntrack --ctstate INVALID -j DROP
// -A KUBE-FORWARD -m comment --comment "kubernetes forwarding rules" -m mark --mark 0x4000/0x4000 -j ACCEPT
// -A KUBE-FORWARD -s 57.112.0.0/12 -m comment --comment "kubernetes forwarding conntrack pod source rule" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
// -A KUBE-FORWARD -d 57.112.0.0/12 -m comment --comment "kubernetes forwarding conntrack pod destination rule" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

// -A KUBE-SERVICES -d 57.131.151.19/32 -p tcp -m comment --comment "default/portal:portal has no endpoints" -m tcp --dport 8989 -j REJECT --reject-with icmp-port-unreachable

const (
	k8sFilterInput       = "k8s-filter-input"
	k8sFilterOutput      = "k8s-filter-output"
	k8sFilterForward     = "k8s-filter-forward"
	k8sFilterExtServices = "k8s-filter-ext-services"
	k8sFilterFirewall    = "k8s-filter-firewall"
	k8sFilterServices    = "k8s-filter-services"
)

func setActionVerdict(key int, chain ...string) *nftableslib.RuleAction {
	ra, err := nftableslib.SetVerdict(key, chain...)
	if err != nil {
		fmt.Printf("failed to SetVerdict with error: %+v\n", err)
		return nil
	}
	return ra
}

func setIPAddr(addr string) *nftableslib.IPAddr {
	a, err := nftableslib.NewIPAddr(addr)
	if err != nil {
		fmt.Printf("error %+v return from NewIPAddr for address: %s\n", err, addr)
		return nil
	}
	return a
}

func setupFilterChains(ci nftableslib.ChainsInterface) error {
	// filter type chains
	filterChains := []struct {
		name  string
		attrs *nftableslib.ChainAttributes
	}{
		{
			name: k8sFilterInput,
			attrs: &nftableslib.ChainAttributes{
				Type:     nftables.ChainTypeFilter,
				Priority: 0,
				Hook:     nftables.ChainHookInput,
				Policy:   nftableslib.ChainPolicyAccept,
			},
		},
		{
			name: k8sFilterOutput,
			attrs: &nftableslib.ChainAttributes{
				Type:     nftables.ChainTypeFilter,
				Priority: 0,
				Hook:     nftables.ChainHookOutput,
				Policy:   nftableslib.ChainPolicyAccept,
			},
		},
		{
			name: k8sFilterForward,
			attrs: &nftableslib.ChainAttributes{
				Type:     nftables.ChainTypeFilter,
				Priority: 0,
				Hook:     nftables.ChainHookForward,
				Policy:   nftableslib.ChainPolicyAccept,
			},
		},
		{
			name:  k8sFilterExtServices,
			attrs: nil,
		},
		{
			name:  k8sFilterFirewall,
			attrs: nil,
		},
		{
			name:  k8sFilterServices,
			attrs: nil,
		},
	}
	for _, chain := range filterChains {
		if err := ci.Chains().CreateImm(chain.name, chain.attrs); err != nil {
			return fmt.Errorf("failed to create chain %s with error: %+v", chain.name, err)
		}
	}

	return nil
}

func setupInitialFilterRules(ci nftableslib.ChainsInterface) error {

	inputRules := []nftableslib.Rule{}
	  
	return nil
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

	ci, err := ti.Tables().TableChains("ipv4table", nftables.TableFamilyIPv4)
	if err != nil {
		fmt.Printf("Failed to get chains interface for table ipv4table with error: %+v\n", err)
		os.Exit(1)
	}

	if err := setupFilterChains(ci); err != nil {
		fmt.Printf("Failed to setup filter chains with error: %+v\n", err)
		os.Exit(1)
	}

	/*
		// nat type chains
		inNetAttr := nftableslib.ChainAttributes{
			Type:     nftables.ChainTypeNAT,
			Priority: 0,
			Hook:     nftables.ChainHookInput,
			Policy:   nftableslib.ChainPolicyAccept,
		}

		inLocalAttr := nftableslib.ChainAttributes{
			Type:     nftables.ChainTypeNAT,
			Priority: 0,
			Hook:     nftables.ChainHookOutput,
			Policy:   nftableslib.ChainPolicyAccept,
		}

		// Deal with packets coming from a node's outside network
		if err := ci.Chains().CreateImm("input-net", &inNetAttr); err != nil {
			fmt.Printf("Failed to chain  input-net for table ipv4table with error: %+v\n", err)
			os.Exit(1)
		}
		// Deal with packets coming from a node's local processes
		if err := ci.Chains().CreateImm("input-local", &inLocalAttr); err != nil {
			fmt.Printf("Failed to chain  input-local for table ipv4table with error: %+v\n", err)
			os.Exit(1)
		}

		// Converged chain of requests to services
		if err := ci.Chains().CreateImm("services", nil); err != nil {
			fmt.Printf("Failed to chain  services for table ipv4table with error: %+v\n", err)
			os.Exit(1)
		}

		// Emulating 2 sets for services without endpoints
		si, err := ti.Tables().TableSets("ipv4table", nftables.TableFamilyIPv4)
		if err != nil {
			fmt.Printf("Failed to get sets interface for table ipv4table with error: %+v\n", err)
			os.Exit(1)
		}

		noEndpointSvcPort := nftableslib.SetAttributes{
			Name:     "no-endpoint-svc-ports",
			Constant: false,
			IsMap:    false,
			KeyType:  nftables.TypeInetService,
		}
		se := []nftables.SetElement{
			{
				Key: binaryutil.BigEndian.PutUint16(8080),
			},
			{
				Key: binaryutil.BigEndian.PutUint16(8989),
			},
		}
		noEndpointPortSet, err := si.Sets().CreateSet(&noEndpointSvcPort, se)
		if err != nil {
			fmt.Printf("Failed to create a set of svc ports without endpoints with error: %+v\n", err)
			os.Exit(1)
		}
		noEndpointSvcAddr := nftableslib.SetAttributes{
			Name:     "no-endpoint-svc-addrs",
			Constant: false,
			KeyType:  nftables.TypeIPAddr,
		}
		se2 := []*nftableslib.IPAddrElement{
			{
				Addr: "10.1.1.1",
			},
			{
				Addr: "10.1.1.2",
			},
		}

		elements := []nftables.SetElement{}
		for _, e := range se2 {
			se, _ := nftableslib.MakeIPAddrElement(e)
			elements = append(elements, se...)
		}
		noEndpointAddrSet, err := si.Sets().CreateSet(&noEndpointSvcAddr, elements)
		if err != nil {
			fmt.Printf("Failed to create a set svc addresses  without endpoint with error: %+v\n", err)
			os.Exit(1)
		}

		// Creating a rule to Reject packets coming to services without endpoints
		// two previously defined sets are used to match
		tcpResetAction, _ := nftableslib.SetReject(unix.NFT_REJECT_TCP_RST, unix.NFT_REJECT_TCP_RST)
		otherRejectAction, _ := nftableslib.SetReject(unix.NFT_REJECT_ICMP_UNREACH, unix.NFT_REJECT_ICMP_UNREACH)

		tcpRejectRule := nftableslib.Rule{
			L3: &nftableslib.L3Rule{
				Dst: &nftableslib.IPAddrSpec{
					SetRef: &nftableslib.SetRef{
						Name:  noEndpointAddrSet.Name,
						ID:    noEndpointAddrSet.ID,
						IsMap: false,
					},
				},
			},
			L4: &nftableslib.L4Rule{
				L4Proto: unix.IPPROTO_TCP,
				Dst: &nftableslib.Port{
					SetRef: &nftableslib.SetRef{
						Name:  noEndpointPortSet.Name,
						ID:    noEndpointPortSet.ID,
						IsMap: false,
					},
				},
			},
			Action: tcpResetAction,
		}

		otherRejectRule := nftableslib.Rule{
			L3: &nftableslib.L3Rule{
				Dst: &nftableslib.IPAddrSpec{
					SetRef: &nftableslib.SetRef{
						Name:  noEndpointAddrSet.Name,
						ID:    noEndpointAddrSet.ID,
						IsMap: false,
					},
				},
			},
			L4: &nftableslib.L4Rule{
				L4Proto: unix.IPPROTO_UDP,
				Dst: &nftableslib.Port{
					SetRef: &nftableslib.SetRef{
						Name:  noEndpointPortSet.Name,
						ID:    noEndpointPortSet.ID,
						IsMap: false,
					},
				},
			},
			Action: otherRejectAction,
		}

		svcri, err := ci.Chains().Chain("services")
		if err != nil {
			fmt.Printf("Failed to get rules interface for chain services with error: %+v\n", err)
			os.Exit(1)
		}

		if _, err := svcri.Rules().CreateImm(&tcpRejectRule); err != nil {
			fmt.Printf("Failed to create initial jump rule to services chain with error: %+v\n", err)
			os.Exit(1)
		}

		if _, err := svcri.Rules().CreateImm(&otherRejectRule); err != nil {
			fmt.Printf("Failed to create initial jump rule to services chain with error: %+v\n", err)
			os.Exit(1)
		}

		// Define rule to jump from ingress chains to services chain
		ra, _ := nftableslib.SetVerdict(unix.NFT_JUMP, "services")
		firstJump := nftableslib.Rule{
			Action: ra,
		}

		c1ri, err := ci.Chains().Chain("input-net")
		if err != nil {
			fmt.Printf("Failed to get rules interface for chain input-net with error: %+v\n", err)
			os.Exit(1)
		}
		c2ri, err := ci.Chains().Chain("input-local")
		if err != nil {
			fmt.Printf("Failed to get rules interface for chain input-local with error: %+v\n", err)
			os.Exit(1)
		}

		if _, err := c1ri.Rules().CreateImm(&firstJump); err != nil {
			fmt.Printf("Failed to create initial jump rule to services chain with error: %+v\n", err)
			os.Exit(1)
		}

		if _, err := c2ri.Rules().CreateImm(&firstJump); err != nil {
			fmt.Printf("Failed to create initial jump rule to services chain with error: %+v\n", err)
			os.Exit(1)
		}

		// Emulating service with endpoints

		svc1EndpointAddr := nftableslib.SetAttributes{
			Name:     "svc1-endpoint-addrs",
			Constant: false,
			KeyType:  nftables.TypeIPAddr,
		}
		se2 = []*nftableslib.IPAddrElement{
			{
				Addr: "12.1.1.1",
			},
			{
				Addr: "12.1.1.2",
			},
		}
		elements = elements[:0]
		for _, e := range se2 {
			se, _ := nftableslib.MakeIPAddrElement(e)
			elements = append(elements, se...)
		}
		 _, err = si.Sets().CreateSet(&svc1EndpointAddr, elements)
		if err != nil {
			fmt.Printf("Failed to create a set svc addresses  without endpoint with error: %+v\n", err)
			os.Exit(1)
		}
		svc2EndpointAddr := nftableslib.SetAttributes{
			Name:     "svc2-endpoint-addrs",
			Constant: false,
			KeyType:  nftables.TypeIPAddr,
		}
		se2 = []*nftableslib.IPAddrElement{
			{
				Addr: "12.1.1.3",
			},
			{
				Addr: "12.1.1.4",
			},
		}
		elements = elements[:0]
		for _, e := range se2 {
			se, _ := nftableslib.MakeIPAddrElement(e)
			elements = append(elements, se...)
		}
		 _, err = si.Sets().CreateSet(&svc2EndpointAddr, elements)
		if err != nil {
			fmt.Printf("Failed to create a set svc addresses  without endpoint with error: %+v\n", err)
			os.Exit(1)
		}

			svc1Rule := nftableslib.Rule{
				L3: &nftableslib.L3Rule{
					Dst: &nftableslib.IPAddrSpec{},
				},
				L4: &nftableslib.L4Rule{
					L4Proto: unix.IPPROTO_TCP,
					Dst: &nftableslib.Port{
						List: []*uint16{},
					},
				},
			}

			svc2Rule := nftableslib.Rule{
				L3: &nftableslib.L3Rule{
					Dst: &nftableslib.IPAddrSpec{},
				},
				L4: &nftableslib.L4Rule{
					L4Proto: unix.IPPROTO_TCP,
					Dst: &nftableslib.Port{
						List: []*uint16{},
					},
				},
			}
	*/
}
