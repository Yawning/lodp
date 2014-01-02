include_directories("${CMAKE_CURRENT_SOURCE_DIR}")

# Embedded third party code.
set(ext_SRCS
  ext/blake2s-ref.c
  ext/curve25519-donna.c
  ext/chacha.c
# ext/chacha_blocks_ref.c
  ext/chacha_blocks_x86-64.S
  ext/siphash.c
)

#add_definitions(-Dchacha_blocks_impl=chacha_blocks_ref
#  -Dhchacha_impl=hchacha_ref)
add_definitions(-Dchacha_blocks_impl=chacha_blocks_x86
  -Dhchacha_impl=hchacha_x86)

# The (Generated) LODP Protobuf code
PROTOBUF_GENERATE_CPP(LODP_PROTO_SRC LODP_PROTO_HEADER schwanenlied/lodp/lodp.proto)
add_definitions(-DGOOGLE_PROTOBUF_NO_RTTI)
get_filename_component(PROTO_HEADER_DIR ${LODP_PROTO_HEADER} PATH) 
include_directories(${PROTO_HEADER_DIR})

PROTOBUF_GENERATE_CPP(NQTCP_PROTO_SRC NQTCP_PROTO_HEADER schwanenlied/nqtcp/nqtcp.proto)

# The actual LODP code
set(lodpxx_SRCS
  schwanenlied/crypto/blake2s.cc
  schwanenlied/crypto/curve25519.cc
  schwanenlied/crypto/hkdf_blake2s.cc
  schwanenlied/crypto/ntor.cc
  schwanenlied/crypto/random.cc
  schwanenlied/crypto/siphash.cc
  schwanenlied/crypto/siv_blake2s_xchacha.cc
  schwanenlied/crypto/utils.cc
  schwanenlied/crypto/xchacha.cc
  schwanenlied/lodp/lodp_endpoint.cc
  schwanenlied/lodp/lodp_session.cc
  schwanenlied/bloom_filter.cc
  schwanenlied/ip_address.cc
  ${LODP_PROTO_SRC}
  ${NQTCP_PROTO_SRC}
)

# Unit tests
add_library(gtest gtest/gtest-all.cc)
add_library(gtest_main gtest/gtest_main.cc)

set(lodpxx_test_SRCS
  schwanenlied/crypto/blake2s_test.cc
  schwanenlied/crypto/curve25519_test.cc
  schwanenlied/crypto/hkdf_blake2s_test.cc
  schwanenlied/crypto/ntor_test.cc
  schwanenlied/crypto/random_test.cc
  schwanenlied/crypto/siphash_test.cc
  schwanenlied/crypto/siv_blake2s_xchacha_test.cc
  schwanenlied/crypto/utils_test.cc
  schwanenlied/crypto/xchacha_test.cc
  schwanenlied/lodp/lodp_test.cc
  schwanenlied/bloom_filter_test.cc
  schwanenlied/ip_address_test.cc
)

add_executable(lodpxx_test ${lodpxx_test_SRCS})
target_link_libraries(lodpxx_test
  lodpxx
  ${PROTOBUF_LITE_LIBRARY}
  ${CMAKE_THREAD_LIBS_INIT}
  libottery
  gtest
  gtest_main
)
add_test(lodpxx_test lodpxx_test)

add_library(lodpxx ${lodpxx_SRCS} ${ext_SRCS})
