include_directories("${PROJECT_SOURCE_DIR}/include")
link_directories("${liblodp_BINARY_DIR}/src")

add_executable(lodp_test lodp_test.c)
target_link_libraries(lodp_test lodp libottery)
