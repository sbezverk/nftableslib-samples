module svcrule

go 1.12

require (
	github.com/google/nftables v0.0.0-20191115091743-3ba45f5d7848
	github.com/sbezverk/nftableslib v0.0.0-20191115163904-f880d8e94afe
	golang.org/x/net v0.0.0-20191125084936-ffdde1057850 // indirect
	golang.org/x/sys v0.0.0-20191120155948-bd437916bb0e
)

replace (
	github.com/google/nftables => ../../../nftables
	github.com/sbezverk/nftableslib => ../../../nftableslib
)
