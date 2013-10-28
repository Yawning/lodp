include_directories("${PROJECT_SOURCE_DIR}/include")
include_directories("./ext")

set(lodp_SRCS
	ext/curve25519-donna.c
	ext/blake2s-ref.c
	ext/chacha.c
	ext/chacha_blocks_ref.c
	ext/siphash.c
	lodp.c
	lodp_crypto.c
	lodp_impl.c
	lodp_pkt.c
)

add_definitions(-Dchacha_blocks_impl=chacha_blocks_ref
		-Dhchacha_impl=hchacha_ref)

add_library(lodp ${lodp_SRCS})

