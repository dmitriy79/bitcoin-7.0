
make -j8 -f makefile.unix OPENSSL_INCLUDE_PATH=/usr/local/ssl/include OPENSSL_LIB_PATH=/usr/local/ssl/lib BOOST_INCLUDE_PATH=/usr/local/include BOOST_LIB_PATH=/usr/local/lib USE_UPNP=-

==================

make -f makefile.mingw -j8
