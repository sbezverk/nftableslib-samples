module github.com/sbezverk/nftableslib-samples/proxy/mimic-filter

go 1.13

require (
	github.com/google/nftables v0.0.0-20191115091743-3ba45f5d7848
	github.com/sbezverk/nftableslib v0.0.0-20191115163904-f880d8e94afe
	golang.org/x/sys v0.0.0-20191128015809-6d18c012aee9
)

replace (
	github.com/google/nftables => ../../../nftables
	github.com/sbezverk/nftableslib => ../../../nftableslib
)
