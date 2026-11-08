// Device durability for the binding's otherwise unsynchronized single WAL.
#include <errno.h>
#include <fcntl.h>
#include <node_api.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

static napi_value sync_file(napi_env env, napi_callback_info info) {
  size_t argc = 1;
  napi_value arg;
  int32_t fd;
  if (napi_get_cb_info(env, info, &argc, &arg, NULL, NULL) != napi_ok ||
      argc != 1 || napi_get_value_int32(env, arg, &fd) != napi_ok) {
    napi_throw_type_error(env, NULL, "expected an open file descriptor");
    return NULL;
  }
  int rc;
  do {
#ifdef __APPLE__
    rc = fcntl(fd, F_FULLFSYNC);
#else
    rc = fsync(fd);
#endif
  } while (rc < 0 && errno == EINTR);
  if (rc < 0) {
    napi_throw_error(env, NULL, strerror(errno));
    return NULL;
  }
  napi_value result;
  napi_get_undefined(env, &result);
  return result;
}

static napi_value init(napi_env env, napi_value exports) {
  napi_value fn;
  if (napi_create_function(env, "syncFile", NAPI_AUTO_LENGTH, sync_file, NULL, &fn) != napi_ok)
    return NULL;
  return fn;
}
NAPI_MODULE(indexer_sync, init)
