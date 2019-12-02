package main

import (
	"fmt"
	"net"
	"os"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/sbezverk/nftableslib"
	"golang.org/x/sys/unix"
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
	filterInput       = "filter-input"
	filterOutput      = "filter-output"
	filterForward     = "filter-forward"
	k8sFilterFirewall = "k8s-filter-firewall"
	k8sFilterServices = "k8s-filter-services"
	k8sFilterForward  = "k8s-filter-forward"
	k8sFilterDoReject = "k8s-filter-do-reject"
)

var (
	ctStateNew         uint32 = 0x08000000
	ctStateRelated     uint32 = 0x04000000
	ctStateEstablished uint32 = 0x02000000
	ctStateInvalid     uint32 = 0x01000000
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
			name: filterInput,
			attrs: &nftableslib.ChainAttributes{
				Type:     nftables.ChainTypeFilter,
				Priority: 0,
				Hook:     nftables.ChainHookInput,
				Policy:   nftableslib.ChainPolicyAccept,
			},
		},
		{
			name: filterOutput,
			attrs: &nftableslib.ChainAttributes{
				Type:     nftables.ChainTypeFilter,
				Priority: 0,
				Hook:     nftables.ChainHookOutput,
				Policy:   nftableslib.ChainPolicyAccept,
			},
		},
		{
			name: filterForward,
			attrs: &nftableslib.ChainAttributes{
				Type:     nftables.ChainTypeFilter,
				Priority: 0,
				Hook:     nftables.ChainHookForward,
				Policy:   nftableslib.ChainPolicyAccept,
			},
		},
		{
			name:  k8sFilterFirewall,
			attrs: nil,
		},
		{
			name:  k8sFilterServices,
			attrs: nil,
		},
		{
			name:  k8sFilterForward,
			attrs: nil,
		},
		{
			name:  k8sFilterDoReject,
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
	inputRules := []nftableslib.Rule{
		{
			// -A INPUT -m conntrack --ctstate NEW -m comment --comment "kubernetes service portals" -j KUBE-SERVICES
			Conntracks: []*nftableslib.Conntrack{
				{
					Key:   unix.NFT_CT_STATE,
					Value: binaryutil.BigEndian.PutUint32(ctStateNew),
				},
			},
			Action: setActionVerdict(unix.NFT_JUMP, k8sFilterServices),
		},
		{
			// -A INPUT -j KUBE-FIREWALL
			Action: setActionVerdict(unix.NFT_JUMP, k8sFilterFirewall),
		},
	}
	// Programming rules for Filter Chain Input hook
	ri, err := ci.Chains().Chain(filterInput)
	if err != nil {
		return err
	}
	for _, r := range inputRules {
		_, err := ri.Rules().CreateImm(&r)
		if err != nil {
			return err
		}
	}
	forwardRules := []nftableslib.Rule{
		{
			// -A FORWARD -m comment --comment "kubernetes forwarding rules" -j KUBE-FORWARD
			Action: setActionVerdict(unix.NFT_JUMP, k8sFilterForward),
		},
		{
			// -A FORWARD -m conntrack --ctstate NEW -m comment --comment "kubernetes service portals" -j KUBE-SERVICES
			Conntracks: []*nftableslib.Conntrack{
				{
					Key:   unix.NFT_CT_STATE,
					Value: binaryutil.BigEndian.PutUint32(ctStateNew),
				},
			},
			Action: setActionVerdict(unix.NFT_JUMP, k8sFilterServices),
		},
	}
	// Programming rules for Filter Chain Forward hook
	ri, err = ci.Chains().Chain(filterForward)
	if err != nil {
		return err
	}
	for _, r := range forwardRules {
		_, err := ri.Rules().CreateImm(&r)
		if err != nil {
			return err
		}
	}
	outputRules := []nftableslib.Rule{
		{
			// -A OUTPUT -m conntrack --ctstate NEW -m comment --comment "kubernetes service portals" -j KUBE-SERVICES
			Conntracks: []*nftableslib.Conntrack{
				{
					Key:   unix.NFT_CT_STATE,
					Value: binaryutil.BigEndian.PutUint32(ctStateNew),
				},
			},
			Action: setActionVerdict(unix.NFT_JUMP, k8sFilterServices),
		},
		{
			// -A OUTPUT -j KUBE-FIREWALL
			Action: setActionVerdict(unix.NFT_JUMP, k8sFilterFirewall),
		},
	}
	// Programming rules for Filter Chain Output hook
	ri, err = ci.Chains().Chain(filterOutput)
	if err != nil {
		return err
	}
	for _, r := range outputRules {
		_, err := ri.Rules().CreateImm(&r)
		if err != nil {
			return err
		}
	}

	firewallRules := []nftableslib.Rule{
		{
			// -A KUBE-FIREWALL -m comment --comment "kubernetes firewall for dropping marked packets" -m mark --mark 0x8000/0x8000 -j DROP
			Meta: &nftableslib.Meta{
				Mark: &nftableslib.MetaMark{
					Set:   false,
					Value: 0x8000,
				},
			},
			Action: setActionVerdict(nftableslib.NFT_DROP),
		},
	}
	// Programming rules for Filter Chain Firewall hook
	ri, err = ci.Chains().Chain(k8sFilterFirewall)
	if err != nil {
		return err
	}
	for _, r := range firewallRules {
		_, err := ri.Rules().CreateImm(&r)
		if err != nil {
			return err
		}
	}

	// -A KUBE-FORWARD -s 57.112.0.0/12 -m comment --comment "kubernetes forwarding conntrack pod source rule" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
	// -A KUBE-FORWARD -d 57.112.0.0/12 -m comment --comment "kubernetes forwarding conntrack pod destination rule" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

	k8sForwardRules := []nftableslib.Rule{
		{
			// -A KUBE-FORWARD -m conntrack --ctstate INVALID -j DROP
			Conntracks: []*nftableslib.Conntrack{
				{
					Key:   unix.NFT_CT_STATE,
					Value: binaryutil.BigEndian.PutUint32(ctStateInvalid),
				},
			},
			Action: setActionVerdict(nftableslib.NFT_DROP),
		},
		{
			// -A KUBE-FORWARD -m comment --comment "kubernetes forwarding rules" -m mark --mark 0x4000/0x4000 -j ACCEPT
			Meta: &nftableslib.Meta{
				Mark: &nftableslib.MetaMark{
					Set:   false,
					Value: 0x4000,
				},
			},
			Action: setActionVerdict(nftableslib.NFT_ACCEPT),
		},
		{
			// -A KUBE-FORWARD -s 57.112.0.0/12 -m comment --comment "kubernetes forwarding conntrack pod source rule" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
			L3: &nftableslib.L3Rule{
				Src: &nftableslib.IPAddrSpec{
					List: []*nftableslib.IPAddr{setIPAddr("57.112.0.0/12")},
				},
			},
			Conntracks: []*nftableslib.Conntrack{
				{
					Key:   unix.NFT_CT_STATE,
					Value: binaryutil.BigEndian.PutUint32(ctStateRelated | ctStateEstablished),
				},
			},
			Action: setActionVerdict(nftableslib.NFT_ACCEPT),
		},
		{
			// -A KUBE-FORWARD -s 57.112.0.0/12 -m comment --comment "kubernetes forwarding conntrack pod source rule" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
			L3: &nftableslib.L3Rule{
				Dst: &nftableslib.IPAddrSpec{
					List: []*nftableslib.IPAddr{setIPAddr("57.112.0.0/12")},
				},
			},
			Conntracks: []*nftableslib.Conntrack{
				{
					Key:   unix.NFT_CT_STATE,
					Value: binaryutil.BigEndian.PutUint32(ctStateRelated | ctStateEstablished),
				},
			},
			Action: setActionVerdict(nftableslib.NFT_ACCEPT),
		},
	}

	// Programming rules for Filter Chain Firewall hook
	ri, err = ci.Chains().Chain(k8sFilterForward)
	if err != nil {
		return err
	}
	for _, r := range k8sForwardRules {
		_, err := ri.Rules().CreateImm(&r)
		if err != nil {
			return err
		}
	}
	rejectAction, _ := nftableslib.SetReject(unix.NFT_REJECT_ICMP_UNREACH, unix.NFT_REJECT_ICMPX_PORT_UNREACH)
	k8sRejectRules := []nftableslib.Rule{
		{
			Action: rejectAction,
		},
	}
	// Programming rules for Filter Chain Firewall hook
	ri, err = ci.Chains().Chain(k8sFilterDoReject)
	if err != nil {
		return err
	}
	for _, r := range k8sRejectRules {
		_, err := ri.Rules().CreateImm(&r)
		if err != nil {
			return err
		}
	}

	return nil
}

func setupk8sFilterRules(ti nftableslib.TablesInterface, ci nftableslib.ChainsInterface) error {
	// Emulating 1 ports sets for service without endpoints
	si, err := ti.Tables().TableSets("ipv4table", nftables.TableFamilyIPv4)
	if err != nil {
		return fmt.Errorf("failed to get sets interface for table ipv4table with error: %+v", err)
	}

	noEndpointSet := nftableslib.SetAttributes{
		Name:     "no-endpoints-services",
		Constant: false,
		IsMap:    true,
		KeyType:  nftableslib.GenSetKeyType(nftables.TypeIPAddr, nftables.TypeInetService),
		DataType: nftables.TypeVerdict,
	}
	se := []nftables.SetElement{}
	// It is a hack for now just to see it is working, ip and port will be extracted from the service object
	port1 := uint16(8989)
	ip1 := "192.168.80.104"
	ip2 := "57.131.151.19"
	ra := setActionVerdict(unix.NFT_JUMP, k8sFilterDoReject)
	se1, err := nftableslib.MakeConcatElement(nftables.TypeIPAddr, nftables.TypeInetService,
		nftableslib.ElementValue{IPAddr: net.ParseIP(ip1).To4()}, nftableslib.ElementValue{InetService: &port1}, ra)
	if err != nil {
		return fmt.Errorf("failed to create a concat element with error: %+v", err)
	}
	se2, err := nftableslib.MakeConcatElement(nftables.TypeIPAddr, nftables.TypeInetService,
		nftableslib.ElementValue{IPAddr: net.ParseIP(ip2).To4()}, nftableslib.ElementValue{InetService: &port1}, ra)
	if err != nil {
		return fmt.Errorf("failed to create a concat element with error: %+v", err)
	}
	se = append(se, *se1)
	se = append(se, *se2)
	neSet, err := si.Sets().CreateSet(&noEndpointSet, se)
	if err != nil {
		return fmt.Errorf("failed to create a set of svc ports without endpoints with error: %+v", err)

	}
	concatElements := make([]*nftableslib.ConcatElement, 0)
	concatElements = append(concatElements,
		&nftableslib.ConcatElement{
			EType: nftables.TypeIPAddr,
		},
	)
	concatElements = append(concatElements,
		&nftableslib.ConcatElement{
			EType:  nftables.TypeInetService,
			EProto: unix.IPPROTO_TCP,
		},
	)
	servicesRules := []nftableslib.Rule{
		{
			Concat: &nftableslib.Concat{
				VMap: true,
				SetRef: &nftableslib.SetRef{
					Name:  neSet.Name,
					ID:    neSet.ID,
					IsMap: true,
				},
				Elements: concatElements,
			},
		},
	}
	ri, err := ci.Chains().Chain(k8sFilterServices)
	if err != nil {
		return err
	}
	for _, r := range servicesRules {
		_, err := ri.Rules().CreateImm(&r)
		if err != nil {
			return err
		}
	}

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

	if err := setupInitialFilterRules(ci); err != nil {
		fmt.Printf("Failed to setup filter initial rules with error: %+v\n", err)
		os.Exit(1)
	}

	if err := setupk8sFilterRules(ti, ci); err != nil {
		fmt.Printf("Failed to setup filter initial rules with error: %+v\n", err)
		os.Exit(1)
	}
}
