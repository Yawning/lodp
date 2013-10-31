include_directories("${PROJECT_SOURCE_DIR}/include")
link_directories("${liblodp_BINARY_DIR}/src")

add_executable(lodp_test lodp_test.c)
target_link_libraries(lodp_test lodp libottery m)

add_executable(lodp_bf_test lodp_bf_test.c)
target_link_libraries(lodp_bf_test lodp libottery m)
