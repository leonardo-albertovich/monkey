set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(src
  monkey.c
  mk_lib.c
  mk_fifo.c
  mk_mimetype.c
  mk_vhost.c
  mk_config.c
  mk_user.c
  mk_utils.c
  mk_stream.c
  mk_scheduler.c
  mk_http_base.c
  mk_http_header.c
  mk_http1.c
  mk_http1_parser.c
  mk_http1_thread.c
  mk_http1_header.c
  mk_socket.c
  mk_net.c
  mk_clock.c
  mk_cache.c
  mk_server.c
  mk_kernel.c
  mk_plugin.c
  )

if(MK_HTTP2)
  set(src
    ${src}
    "mk_http2.c"
    "mk_http2_dynamic_table.c"
    "mk_http2_header_table.c"
    "mk_http2_stream.c"
    "mk_http2_hpack.c"
    "mk_http2_huffman.c"
    "mk_http2_request.c"
    "mk_http2_thread.c"
    "mk_http2_frame_decoders.c"
    "mk_http2_frame_encoders.c"
    "mk_http2_frame_handlers.c"
    )
endif()

# Always build a static library, thats our core :)
add_library(monkey-core-static STATIC ${src})
set_target_properties(monkey-core-static PROPERTIES OUTPUT_NAME monkey)
target_link_libraries(monkey-core-static mk_core ${CMAKE_THREAD_LIBS_INIT} ${STATIC_PLUGINS_LIBS} ${CMAKE_DL_LIBS} rbtree co)

message(STATUS "LINKING ${STATIC_PLUGINS_LIBS}")

# Linux Kqueue emulation
if(MK_HAVE_LINUX_KQUEUE)
  target_link_libraries(monkey-core-static kqueue)
endif()

if (CMAKE_SYSTEM_NAME MATCHES "SunOS")
  target_link_libraries(monkey-core-static socket nsl)
endif()
