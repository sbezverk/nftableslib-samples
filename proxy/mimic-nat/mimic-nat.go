package main

import (
	"fmt"
	"os"

	"github.com/google/nftables"
	"github.com/sbezverk/nftableslib"
	"golang.org/x/sys/unix"
)

// -A PREROUTING -m comment --comment "kubernetes service portals" -j KUBE-SERVICES
// -A OUTPUT -m comment --comment "kubernetes service portals" -j KUBE-SERVICES
// -A POSTROUTING -m comment --comment "kubernetes postrouting rules" -j KUBE-POSTROUTING
// -A KUBE-MARK-DROP -j MARK --set-xmark 0x8000/0x8000
// -A KUBE-MARK-MASQ -j MARK --set-xmark 0x4000/0x4000
// -A KUBE-POSTROUTING -m comment --comment "kubernetes service traffic requiring SNAT" -m mark --mark 0x4000/0x4000 -j MASQUERADE
// !
// ! Node ports for services  KUBE-SVC-S4S242M2WNFIAT6Y
// !
// -A KUBE-NODEPORTS -p tcp -m comment --comment "istio-system/istio-ingressgateway:tls" -m tcp --dport 30725 -j KUBE-MARK-MASQ
// -A KUBE-NODEPORTS -p tcp -m comment --comment "istio-system/istio-ingressgateway:tls" -m tcp --dport 30725 -j KUBE-SVC-S4S242M2WNFIAT6Y
// !
// ! KUBE-SVC-S4S242M2WNFIAT6Y
// !
// -A KUBE-SERVICES ! -s 57.112.0.0/12 -d 57.142.35.114/32 -p tcp -m comment --comment "istio-system/istio-ingressgateway:tls cluster IP" -m tcp --dport 15443 -j KUBE-MARK-MASQ
// -A KUBE-SERVICES -d 57.142.35.114/32 -p tcp -m comment --comment "istio-system/istio-ingressgateway:tls cluster IP" -m tcp --dport 15443 -j KUBE-SVC-S4S242M2WNFIAT6Y
// !
// ! KUBE-SVC-57XVOCFNTLTR3Q27
// !
// -A KUBE-SERVICES ! -s 57.112.0.0/12 -d 57.142.221.21/32 -p tcp -m comment --comment "default/app:http-web cluster IP" -m tcp --dport 80 -j KUBE-MARK-MASQ
// -A KUBE-SERVICES -d 57.142.221.21/32 -p tcp -m comment --comment "default/app:http-web cluster IP" -m tcp --dport 80 -j KUBE-SVC-57XVOCFNTLTR3Q27
// !
// ! For externally exposed service portal
// !
// -A KUBE-SERVICES -d 57.131.151.19/32 -p tcp -m comment --comment "default/portal:portal cluster IP" -m tcp --dport 8989 -j KUBE-SVC-MUPXPVK4XAZHSWAR
// -A KUBE-SERVICES -d 192.168.80.104/32 -p tcp -m comment --comment "default/portal:portal external IP" -m tcp --dport 8989 -j KUBE-MARK-MASQ
// -A KUBE-SERVICES -d 192.168.80.104/32 -p tcp -m comment --comment "default/portal:portal external IP" -m tcp --dport 8989 -m physdev ! --physdev-is-in -m addrtype ! --src-type LOCAL -j KUBE-SVC-MUPXPVK4XAZHSWAR
// -A KUBE-SERVICES -d 192.168.80.104/32 -p tcp -m comment --comment "default/portal:portal external IP" -m tcp --dport 8989 -m addrtype --dst-type LOCAL -j KUBE-SVC-MUPXPVK4XAZHSWAR
// !
// ! Service entry for KUBE-SVC-S4S242M2WNFIAT6Y
// !
// -A KUBE-SVC-S4S242M2WNFIAT6Y -j KUBE-SEP-CUAZ6PSSTEDPJ43V
// !
// ! Service entry for KUBE-SVC-57XVOCFNTLTR3Q27
// !
// -A KUBE-SVC-57XVOCFNTLTR3Q27 -m statistic --mode random --probability 0.50000000000 -j KUBE-SEP-FS3FUULGZPVD4VYB
// -A KUBE-SVC-57XVOCFNTLTR3Q27 -j KUBE-SEP-MMFZROQSLQ3DKOQA
// !
// ! Service entry for KUBE-SVC-MUPXPVK4XAZHSWAR
// !
// -A KUBE-SVC-MUPXPVK4XAZHSWAR -j KUBE-SEP-LO6TEVOI6GV524F3
// !
// ! Endpoint 1 for KUBE-SVC-57XVOCFNTLTR3Q27
// !
// -A KUBE-SEP-FS3FUULGZPVD4VYB -s 57.112.0.247/32 -j KUBE-MARK-MASQ
// -A KUBE-SEP-FS3FUULGZPVD4VYB -p tcp -m tcp -j DNAT --to-destination 57.112.0.247:8080
// !
// ! Endpoint 2 for KUBE-SVC-57XVOCFNTLTR3Q27
// !
// -A KUBE-SEP-MMFZROQSLQ3DKOQA -s 57.112.0.248/32 -j KUBE-MARK-MASQ
// -A KUBE-SEP-MMFZROQSLQ3DKOQA -p tcp -m tcp -j DNAT --to-destination 57.112.0.248:8080
// !
// ! Endpoint for KUBE-SVC-S4S242M2WNFIAT6Y
// !
// -A KUBE-SEP-CUAZ6PSSTEDPJ43V -s 57.112.0.244/32 -j KUBE-MARK-MASQ
// -A KUBE-SEP-CUAZ6PSSTEDPJ43V -p tcp -m tcp -j DNAT --to-destination 57.112.0.244:15443
// !
// ! Endpoint for KUBE-SVC-MUPXPVK4XAZHSWAR
// !
// -A KUBE-SEP-LO6TEVOI6GV524F3 -s 57.112.0.250/32 -j KUBE-MARK-MASQ
// -A KUBE-SEP-LO6TEVOI6GV524F3 -p tcp -m tcp -j DNAT --to-destination 57.112.0.250:38989

const (
	natPrerouting     = "nat-preroutin"
	natOutput         = "nat-output"
	natPostrouting    = "nat-postrouting"
	k8sNATMarkDrop    = "k8s-nat-mark-drop"
	k8sNATMarkMasq    = "k8s-nat-mark-masq"
	k8sNATServices    = "k8s-nat-services"
	k8sNATNodeports   = "k8s-nat-nodeports"
	k8sNATPostrouting = "k8s-nat-postrouting"
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

func setupNATChains(ci nftableslib.ChainsInterface) error {
	// nat type chains
	natChains := []struct {
		name  string
		attrs *nftableslib.ChainAttributes
	}{
		{
			name: natPrerouting,
			attrs: &nftableslib.ChainAttributes{
				Type:     nftables.ChainTypeNAT,
				Priority: 0,
				Hook:     nftables.ChainHookPrerouting,
				Policy:   nftableslib.ChainPolicyAccept,
			},
		},
		{
			name: natOutput,
			attrs: &nftableslib.ChainAttributes{
				Type:     nftables.ChainTypeNAT,
				Priority: 0,
				Hook:     nftables.ChainHookOutput,
				Policy:   nftableslib.ChainPolicyAccept,
			},
		},
		{
			name: natPostrouting,
			attrs: &nftableslib.ChainAttributes{
				Type:     nftables.ChainTypeNAT,
				Priority: 0,
				Hook:     nftables.ChainHookPostrouting,
				Policy:   nftableslib.ChainPolicyAccept,
			},
		},
		{
			name:  k8sNATMarkDrop,
			attrs: nil,
		},
		//		{
		//			name:  k8sNATMarkMasq,
		//			attrs: nil,
		//		},
		{
			name:  k8sNATServices,
			attrs: nil,
		},
		{
			name:  k8sNATNodeports,
			attrs: nil,
		},
		{
			name:  k8sNATPostrouting,
			attrs: nil,
		},
	}
	for _, chain := range natChains {
		if err := ci.Chains().CreateImm(chain.name, chain.attrs); err != nil {
			return fmt.Errorf("failed to create chain %s with error: %+v", chain.name, err)
		}
	}

	return nil
}

func setupInitialNATRules(ci nftableslib.ChainsInterface) error {
	preroutingRules := []nftableslib.Rule{
		{
			// -A PREROUTING -m comment --comment "kubernetes service portals" -j KUBE-SERVICES
			Action: setActionVerdict(unix.NFT_JUMP, k8sNATServices),
		},
	}
	// Programming rules for nat Chain Prerouting hook
	ri, err := ci.Chains().Chain(natPrerouting)
	if err != nil {
		return err
	}
	for _, r := range preroutingRules {
		_, err := ri.Rules().CreateImm(&r)
		if err != nil {
			return err
		}
	}
	outputRules := []nftableslib.Rule{
		{
			// -A OUTPUT -m comment --comment "kubernetes service portals" -j KUBE-SERVICES
			Action: setActionVerdict(unix.NFT_JUMP, k8sNATServices),
		},
	}
	// Programming rules for nat Chain Output hook
	ri, err = ci.Chains().Chain(natOutput)
	if err != nil {
		return err
	}
	for _, r := range outputRules {
		_, err := ri.Rules().CreateImm(&r)
		if err != nil {
			return err
		}
	}
	postroutingRules := []nftableslib.Rule{
		{
			// -A POSTROUTING -m comment --comment "kubernetes postrouting rules" -j KUBE-POSTROUTING
			Action: setActionVerdict(unix.NFT_JUMP, k8sNATPostrouting),
		},
	}
	// Programming rules for nat Chain Postrouting hook
	ri, err = ci.Chains().Chain(natPostrouting)
	if err != nil {
		return err
	}
	for _, r := range postroutingRules {
		_, err := ri.Rules().CreateImm(&r)
		if err != nil {
			return err
		}
	}

	markDropRules := []nftableslib.Rule{
		{
			// -A KUBE-MARK-DROP -j MARK --set-xmark 0x8000/0x8000
			Meta: &nftableslib.Meta{
				Mark: &nftableslib.MetaMark{
					Set:   true,
					Value: 0x8000,
				},
			},
		},
	}
	// Programming rules for k8s Chain k8s-nat-mark-drop
	ri, err = ci.Chains().Chain(k8sNATMarkDrop)
	if err != nil {
		return err
	}
	for _, r := range markDropRules {
		_, err := ri.Rules().CreateImm(&r)
		if err != nil {
			return err
		}
	}

	//	markMasqRules := []nftableslib.Rule{
	//		{
	//			// -A KUBE-MARK-MASQ -j MARK --set-xmark 0x4000/0x4000
	//			Meta: &nftableslib.Meta{
	//				Mark: &nftableslib.MetaMark{
	//					Set:   true,
	//					Value: 0x4000,
	//				},
	//			},
	//		},
	//	}
	// Programming rules for k8s Chain k8s-nat-mark-masq
	//	ri, err = ci.Chains().Chain(k8sNATMarkMasq)
	//	if err != nil {
	//		return err
	//	}
	//	for _, r := range markMasqRules {
	//		_, err := ri.Rules().CreateImm(&r)
	//		if err != nil {
	//			return err
	//		}
	//	}

	masqAction, _ := nftableslib.SetMasq(true, false, true)
	k8sPostroutingRules := []nftableslib.Rule{
		{
			// -A KUBE-POSTROUTING -m comment --comment "kubernetes service traffic requiring SNAT" -m mark --mark 0x4000/0x4000 -j MASQUERADE
			Meta: &nftableslib.Meta{
				Mark: &nftableslib.MetaMark{
					Set:   false,
					Value: 0x4000,
				},
			},
			Action: masqAction,
		},
	}

	// Programming rules for Filter Chain Firewall hook
	ri, err = ci.Chains().Chain(k8sNATPostrouting)
	if err != nil {
		return err
	}
	for _, r := range k8sPostroutingRules {
		_, err := ri.Rules().CreateImm(&r)
		if err != nil {
			return err
		}
	}

	return nil
}

func setupk8sNATNodeportRules(ti nftableslib.TablesInterface, ci nftableslib.ChainsInterface) error {
	_, err := ti.Tables().TableSets("ipv4table", nftables.TableFamilyIPv4)
	if err != nil {
		return fmt.Errorf("failed to get sets interface for table ipv4table with error: %+v", err)
	}
	if err := ci.Chains().CreateImm("KUBE-SVC-S4S242M2WNFIAT6Y", nil); err != nil {
		return fmt.Errorf("failed to create chain KUBE-SVC-S4S242M2WNFIAT6Y with error: %+v", err)
	}
	nodeportRules := []nftableslib.Rule{
		//		{
		// -A KUBE-NODEPORTS -p tcp -m comment --comment "istio-system/istio-ingressgateway:tls" -m tcp --dport 30725 -j KUBE-MARK-MASQ
		//			L4: &nftableslib.L4Rule{
		//				L4Proto: unix.IPPROTO_TCP,
		//				Dst: &nftableslib.Port{
		//					List: nftableslib.SetPortList([]int{30725}),
		//				},
		//			},
		//			Action: setActionVerdict(unix.NFT_JUMP, k8sNATMarkMasq),
		//		},
		{
			// -A KUBE-NODEPORTS -p tcp -m comment --comment "istio-system/istio-ingressgateway:tls" -m tcp --dport 30725 -j KUBE-MARK-MASQ
			// -A KUBE-NODEPORTS -p tcp -m comment --comment "istio-system/istio-ingressgateway:tls" -m tcp --dport 30725 -j KUBE-SVC-S4S242M2WNFIAT6Y
			L4: &nftableslib.L4Rule{
				L4Proto: unix.IPPROTO_TCP,
				Dst: &nftableslib.Port{
					List: nftableslib.SetPortList([]int{30725}),
				},
			},
			Meta: &nftableslib.Meta{
				Mark: &nftableslib.MetaMark{
					Set:   true,
					Value: 0x4000,
				},
			},
			Action: setActionVerdict(unix.NFT_JUMP, "KUBE-SVC-S4S242M2WNFIAT6Y"),
		},
	}
	ri, err := ci.Chains().Chain(k8sNATNodeports)
	if err != nil {
		return err
	}
	for _, r := range nodeportRules {
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

	if err := setupNATChains(ci); err != nil {
		fmt.Printf("Failed to setup nat chains with error: %+v\n", err)
		os.Exit(1)
	}

	if err := setupInitialNATRules(ci); err != nil {
		fmt.Printf("Failed to setup nat initial rules with error: %+v\n", err)
		os.Exit(1)
	}

	if err := setupk8sNATNodeportRules(ti, ci); err != nil {
		fmt.Printf("Failed to setup nat initial rules with error: %+v\n", err)
		os.Exit(1)
	}
}
