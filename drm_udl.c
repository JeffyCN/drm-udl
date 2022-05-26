/*
 * Copyright (c) 2022, Jeffy Chen <jeffy.chen@rock-chips.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/time.h>

#include <pthread.h>

#include <xf86drm.h>
#include <xf86drmMode.h>

#include <drm_fourcc.h>

#define LIBDRM_UDL_VERSION "1.0.0~20220428"

static int drm_debug = 0;
static FILE *log_fp = NULL;

#define LOG_FILE (log_fp ? log_fp : stderr)
#define DRM_LOG(tag, ...) { \
  struct timeval tv; gettimeofday(&tv, NULL); \
  fprintf(LOG_FILE, "[%05ld.%03ld] " tag ": %s(%d) ", \
          tv.tv_sec % 100000, tv.tv_usec / 1000, __func__, __LINE__); \
  fprintf(LOG_FILE, __VA_ARGS__); fflush(LOG_FILE); }

#define DRM_DEBUG(...) if (drm_debug) DRM_LOG("DRM_DEBUG", __VA_ARGS__)
#define DRM_INFO(...) DRM_LOG("DRM_INFO", __VA_ARGS__)
#define DRM_ERROR(...) DRM_LOG("DRM_ERROR", __VA_ARGS__)

#undef ARRAY_SIZE
#define ARRAY_SIZE(x) (int)(sizeof(x)/sizeof(x[0]))

#undef memclear
#define memclear(s) memset(&s, 0, sizeof(s))

/* Load libdrm symbols */

static drmModeResPtr (* _drmModeGetResources)(int fd) = NULL;
static drmModeFBPtr (* _drmModeGetFB)(int fd, uint32_t bufferId) = NULL;
#ifdef HAS_DRM_MODE_FB2
static drmModeFB2Ptr (* _drmModeGetFB2)(int fd, uint32_t bufferId) = NULL;
#endif
static int (* _drmModeAddFB)(int fd, uint32_t width, uint32_t height,
                             uint8_t depth, uint8_t bpp, uint32_t pitch,
                             uint32_t bo_handle, uint32_t *buf_id) = NULL;
static int (* _drmModeAddFB2)(int fd, uint32_t width, uint32_t height,
                              uint32_t pixel_format, const uint32_t bo_handles[4],
                              const uint32_t pitches[4], const uint32_t offsets[4],
                              uint32_t *buf_id, uint32_t flags) = NULL;
static int (* _drmModeAddFB2WithModifiers)(int fd, uint32_t width, uint32_t height,
                                           uint32_t pixel_format,
                                           const uint32_t bo_handles[4],
                                           const uint32_t pitches[4],
                                           const uint32_t offsets[4],
                                           const uint64_t modifier[4],
                                           uint32_t *buf_id, uint32_t flags) = NULL;
static int (* _drmModeRmFB)(int fd, uint32_t bufferId) = NULL;
static int (* _drmModeDirtyFB)(int fd, uint32_t bufferId,
                               drmModeClipPtr clips, uint32_t num_clips) = NULL;
static drmModeCrtcPtr (* _drmModeGetCrtc)(int fd, uint32_t crtcId) = NULL;
static int (* _drmModeSetCrtc)(int fd, uint32_t crtcId, uint32_t bufferId,
                               uint32_t x, uint32_t y, uint32_t *connectors,
                               int count, drmModeModeInfoPtr mode) = NULL;
static drmModeEncoderPtr (* _drmModeGetEncoder)(int fd,
                                                uint32_t encoder_id) = NULL;
static drmModeConnectorPtr
(* _drmModeGetConnector)(int fd, uint32_t connectorId) = NULL;
static drmModeConnectorPtr
(* _drmModeGetConnectorCurrent)(int fd, uint32_t connector_id) = NULL;
static int (* _drmModeAttachMode)(int fd, uint32_t connectorId,
                                  drmModeModeInfoPtr mode_info) = NULL;
static int (* _drmModeDetachMode)(int fd, uint32_t connectorId,
                                  drmModeModeInfoPtr mode_info) = NULL;
static drmModePropertyPtr
(* _drmModeGetProperty)(int fd, uint32_t propertyId) = NULL;
static drmModePropertyBlobPtr
(* _drmModeGetPropertyBlob)(int fd, uint32_t blob_id) = NULL;
static int (* _drmModeConnectorSetProperty)(int fd, uint32_t connector_id,
                                            uint32_t property_id,
                                            uint64_t value) = NULL;
static int (* _drmModeCrtcSetGamma)(int fd, uint32_t crtc_id, uint32_t size,
                                    uint16_t *red, uint16_t *green,
                                    uint16_t *blue) = NULL;
static int (* _drmModeCrtcGetGamma)(int fd, uint32_t crtc_id, uint32_t size,
                                    uint16_t *red, uint16_t *green,
                                    uint16_t *blue) = NULL;
static int (* _drmModePageFlip)(int fd, uint32_t crtc_id, uint32_t fb_id,
                                uint32_t flags, void *user_data) = NULL;
static int (* _drmModePageFlipTarget)(int fd, uint32_t crtc_id, uint32_t fb_id,
                                      uint32_t flags, void *user_data,
                                      uint32_t target_vblank) = NULL;
static drmModePlaneResPtr (* _drmModeGetPlaneResources)(int fd) = NULL;
static drmModePlanePtr (* _drmModeGetPlane)(int fd, uint32_t plane_id) = NULL;
static int (* _drmModeSetPlane)(int fd, uint32_t plane_id, uint32_t crtc_id,
                                uint32_t fb_id, uint32_t flags,
                                int32_t crtc_x, int32_t crtc_y,
                                uint32_t crtc_w, uint32_t crtc_h,
                                uint32_t src_x, uint32_t src_y,
                                uint32_t src_w, uint32_t src_h) = NULL;
static drmModeObjectPropertiesPtr
(* _drmModeObjectGetProperties)(int fd, uint32_t object_id,
                                uint32_t object_type) = NULL;
static int (* _drmModeObjectSetProperty)(int fd, uint32_t object_id,
                                         uint32_t object_type,
                                         uint32_t property_id,
                                         uint64_t value) = NULL;

#define DRM_SYMBOL(func) { #func, (void **)(&_ ## func), }
static struct {
  const char *func;
  void **symbol;
} drm_symbols[] = {
  DRM_SYMBOL(drmModeGetResources),
  DRM_SYMBOL(drmModeGetFB),
#ifdef HAS_DRM_MODE_FB2
  DRM_SYMBOL(drmModeGetFB2),
#endif
  DRM_SYMBOL(drmModeAddFB),
  DRM_SYMBOL(drmModeAddFB2),
  DRM_SYMBOL(drmModeAddFB2WithModifiers),
  DRM_SYMBOL(drmModeRmFB),
  DRM_SYMBOL(drmModeDirtyFB),
  DRM_SYMBOL(drmModeGetCrtc),
  DRM_SYMBOL(drmModeSetCrtc),
  DRM_SYMBOL(drmModeGetEncoder),
  DRM_SYMBOL(drmModeGetConnector),
  DRM_SYMBOL(drmModeGetConnectorCurrent),
  DRM_SYMBOL(drmModeAttachMode),
  DRM_SYMBOL(drmModeDetachMode),
  DRM_SYMBOL(drmModeGetProperty),
  DRM_SYMBOL(drmModeGetPropertyBlob),
  DRM_SYMBOL(drmModeConnectorSetProperty),
  DRM_SYMBOL(drmModeCrtcSetGamma),
  DRM_SYMBOL(drmModeCrtcGetGamma),
  DRM_SYMBOL(drmModePageFlip),
  DRM_SYMBOL(drmModePageFlipTarget),
  DRM_SYMBOL(drmModeGetPlaneResources),
  DRM_SYMBOL(drmModeGetPlane),
  DRM_SYMBOL(drmModeSetPlane),
  DRM_SYMBOL(drmModeObjectGetProperties),
  DRM_SYMBOL(drmModeObjectSetProperty),
};

__attribute__((constructor)) static void load_drm_symbols(void)
{
  void *handle, *symbol;
  int i;

#define LIBDRM_SO "libdrm.so.2"

  /* The libdrm should be already loaded */
  handle = dlopen(LIBDRM_SO, RTLD_LAZY | RTLD_NOLOAD);
  if (!handle) {
    /* Should not reach here */
    fprintf(stderr, "FATAL: dlopen(" LIBDRM_SO ") failed(%s)\n", dlerror());
    exit(-1);
  }

  for (i = 0; i < ARRAY_SIZE(drm_symbols); i++) {
    const char *func = drm_symbols[i].func;

    /* Clear error */
    dlerror();

    symbol = dlsym(handle, func);
    if (!symbol) {
      /* Should not reach here */
      fprintf(stderr, "FATAL: " LIBDRM_SO " dlsym(%s) failed(%s)\n",
              func, dlerror());
      dlclose(handle);
      exit(-1);
    }

    *drm_symbols[i].symbol = symbol;
  }

  dlclose(handle);
}

#ifndef HAS_DRM_CLOSE_HANDLE
/* From libdrm 2.4.109 : xf86drm.c */
int drmCloseBufferHandle(int fd, uint32_t handle)
{
  struct drm_gem_close args;

  memclear(args);
  args.handle = handle;
  return drmIoctl(fd, DRM_IOCTL_GEM_CLOSE, &args);
}
#endif // HAS_DRM_CLOSE_HANDLE

/* Parsing drm-udl config */

#define DRM_UDL_CONFIG_FILE "/etc/drm-udl.conf"
#define OPT_DEBUG "debug="
#define OPT_LOG_FILE "log-file="
#define OPT_DIRTYFB "dirtyfb-mode="
#define OPT_FORCE_ON "udl-force-on="
#define OPT_HIDDEN "hide-udl="
#define OPT_FULLSCREEN "force-fullscreen="

typedef struct {
  bool valid;

  drmModeClip clip;

  uint32_t fb_id;
  uint32_t flags;

  uint32_t crtc_x;
  uint32_t crtc_y;
  uint32_t crtc_w;
  uint32_t crtc_h;

  uint32_t src_x;
  uint32_t src_y;
  uint32_t src_w;
  uint32_t src_h;
} udl_request;

typedef enum {
  DIRTYFB_MODE_BOTH,
  DIRTYFB_MODE_UDL_ONLY,
  DIRTYFB_MODE_FAKE,
  DIRTYFB_MODE_NONE,
} dirtyfb_mode;

/* Fake an UDL CRTC when not exists */
#define UDL_FLAG_FORCE_ON     (1 << 0)
/* Hide the UDL device */
#define UDL_FLAG_HIDDEN       (1 << 1)

static struct {
  int fd;

  uint32_t crtc_id;
  uint32_t connector_id;
  uint32_t encoder_id;
  uint32_t plane_id;
  drmModeModeInfo mode;

  pthread_t thread;
  pthread_cond_t cond;
  pthread_mutex_t mutex;
  udl_request request;
  uint32_t process_fb_id;

  uint32_t curr_fb_id;

  uint32_t orphane_fb[16];

  dirtyfb_mode dirtyfb_mode;
  int udl_flags;
  bool force_fullscreen;

  const char *configs;

  bool inited;
} udl_ctx = {0,};

static void udl_load_config(const char *file)
{
  struct stat st;
  char *configs = NULL, *ptr, *tmp;
  int fd;

  if (stat(file, &st) < 0)
    return;

  fd = open(file, O_RDONLY);
  if (fd < 0)
    return;

  ptr = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (ptr == MAP_FAILED)
    goto out_close_fd;

  configs = malloc(st.st_size + 1);
  if (!configs)
    goto out_unmap;

  memcpy(configs, ptr, st.st_size);
  configs[st.st_size] = '\0';

  tmp = configs;
  while ((tmp = strchr(tmp, '#'))) {
    while (*tmp != '\n' && *tmp != '\0')
      *tmp++ = '\n';
  }

  udl_ctx.configs = configs;
out_unmap:
  munmap(ptr, st.st_size);
out_close_fd:
  close(fd);
}

static const char *udl_get_config(const char *name, const char *def)
{
  static char buf[4096];
  const char *config;

  if (!udl_ctx.configs)
    return def;

  config = strstr(udl_ctx.configs, name);
  if (!config)
    return def;

  config += strlen(name);
  if (config[0] == '\0' || config[0] == ' ' || config[0] == '\n')
    return def;

  sscanf(config, "%4095s", buf);
  return buf;
}

static int udl_get_config_int(const char *name, int def)
{
  const char *config = udl_get_config(name, NULL);

  if (config)
    return atoi(config);

  return def;
}

static void *udl_thread_fn(void *data);
static void udl_init(void)
{
  const char *config;

  udl_ctx.fd = -1;
  udl_load_config(DRM_UDL_CONFIG_FILE);

  drm_debug = udl_get_config_int(OPT_DEBUG, 0);

  if (getenv("DRM_DEBUG") || !access("/tmp/.drm_udl_debug", F_OK))
    drm_debug = 1;

  if (!(config = getenv("DRM_UDL_LOG_FILE")))
    config = udl_get_config(OPT_LOG_FILE, "/var/log/drm-udl.log");

  log_fp = fopen(config, "wb+");

  config = udl_get_config(OPT_DIRTYFB, "both");
  if (!strcmp(config, "both"))
    udl_ctx.dirtyfb_mode = DIRTYFB_MODE_BOTH;
  else if (!strcmp(config, "udl-only"))
    udl_ctx.dirtyfb_mode = DIRTYFB_MODE_UDL_ONLY;
  else if (!strcmp(config, "fake"))
    udl_ctx.dirtyfb_mode = DIRTYFB_MODE_FAKE;
  else
    udl_ctx.dirtyfb_mode = DIRTYFB_MODE_NONE;

  if (udl_get_config_int(OPT_FORCE_ON, 1))
    udl_ctx.udl_flags |= UDL_FLAG_FORCE_ON;

  if (udl_get_config_int(OPT_HIDDEN, 1))
    udl_ctx.udl_flags |= UDL_FLAG_HIDDEN;

  udl_ctx.force_fullscreen = udl_get_config_int(OPT_FULLSCREEN, 1);

  pthread_cond_init(&udl_ctx.cond, NULL);
  pthread_mutex_init(&udl_ctx.mutex, NULL);
  pthread_create(&udl_ctx.thread, NULL, udl_thread_fn, NULL);

  udl_ctx.inited = true;
  DRM_INFO("using libdrm-udl (%s)\n", LIBDRM_UDL_VERSION);
}

/* Override libdrm APIs */

/* Each DRM device has it's own obj IDR, so we need to wrap UDL's obj IDs */
#define UDL_ID_BASE       (1 << 10)
#define UDL_CRTC_ID       UDL_ID_BASE
#define UDL_PLANE_ID      (UDL_ID_BASE + 1)
#define UDL_CUSTOM_ID     (UDL_PLANE_ID + 1)
#define ID_IS_UDL(id)     ((id) >= UDL_ID_BASE)
#define WRAP_UDL_ID(id)   (assert(!(ID_IS_UDL(id))), (id) + UDL_CUSTOM_ID)
#define UNWRAP_UDL_ID(id) (assert(ID_IS_UDL(id)), (id) - UDL_CUSTOM_ID)

#define UDL_FB_SHIFT      16
#define UDL_FB_MASK       ((1 << UDL_FB_SHIFT) - 1)
#define WRAP_UDL_FB(primary_fb, udl_fb) ((primary_fb) | (udl_fb) << UDL_FB_SHIFT)
#define UDL_FB(fb) ((fb) >> UDL_FB_SHIFT)
#define PRIMARY_FB(fb) ((fb) & UDL_FB_MASK)

#define _UDL_ADD_RES(res, type, count, value) { \
  (res)->type = realloc((res)->type, sizeof(int) * ((res)->count + 1)); \
  (res)->type[(res)->count] = value; \
  (res)->count++; \
}
#define UDL_ADD_RES(res, type, value) \
  _UDL_ADD_RES(res, type, count_ ## type, value)

static inline bool udl_is_udl(int fd)
{
  drmVersionPtr version = drmGetVersion(fd);
  bool is_udl = false;

  if (version && !strcmp(version->name, "udl"))
    is_udl = true;

  drmFreeVersion(version);
  return is_udl;
}

#define UDL_VALID() (!drmSetMaster(udl_ctx.fd))

static inline bool udl_update_status(void)
{
  drmModePlaneResPtr pres;
  drmModeResPtr res;

  if (!udl_ctx.inited)
    udl_init();

  if (UDL_VALID())
    return true;

  pthread_mutex_lock(&udl_ctx.mutex);

  if (udl_ctx.fd >= 0) {
    DRM_DEBUG("UDL disconnected\n");
    close(udl_ctx.fd);
  }

  memclear(udl_ctx.orphane_fb);
  memclear(udl_ctx.request);
  udl_ctx.curr_fb_id = 0;
  udl_ctx.process_fb_id = 0;

  udl_ctx.fd = drmOpen("udl", NULL);
  if (udl_ctx.fd < 0)
    goto err;

  drmSetClientCap(udl_ctx.fd, DRM_CLIENT_CAP_UNIVERSAL_PLANES, 1);

  res = _drmModeGetResources(udl_ctx.fd);
  if (!res)
    goto err_close_fd;

  assert(res->count_crtcs == 1);
  udl_ctx.crtc_id = res->crtcs[0];
  assert(res->count_connectors == 1);
  udl_ctx.connector_id = res->connectors[0];
  assert(res->count_encoders == 1);
  udl_ctx.encoder_id = res->encoders[0];

  drmModeFreeResources(res);

  pres = _drmModeGetPlaneResources(udl_ctx.fd);
  if (!pres)
    goto err_close_fd;

  assert(pres->count_planes == 1);
  udl_ctx.plane_id = pres->planes[0];

  drmModeFreePlaneResources(pres);

  DRM_DEBUG("UDL connected crtc(%d) encoder(%d) connector(%d) plane(%d)\n",
            udl_ctx.crtc_id, udl_ctx.encoder_id,
            udl_ctx.connector_id, udl_ctx.plane_id);

  pthread_cond_signal(&udl_ctx.cond);
  pthread_mutex_unlock(&udl_ctx.mutex);
  return true;
err_close_fd:
  close(udl_ctx.fd);
  udl_ctx.fd = -1;
err:
  pthread_mutex_unlock(&udl_ctx.mutex);
  return false;
}

/* Protect current or pending FB */
#define UDL_FB_UNUSED(id) \
  ((id) && (id) != udl_ctx.curr_fb_id && \
   (id) != udl_ctx.process_fb_id && (id) != udl_ctx.request.fb_id)

static void udl_cleanup_orphane_fb(void)
{
  int i;

  pthread_mutex_lock(&udl_ctx.mutex);
  for (i = 0; i < ARRAY_SIZE(udl_ctx.orphane_fb); i++) {
    if (UDL_FB_UNUSED(udl_ctx.orphane_fb[i])) {
      DRM_DEBUG("rm UDL FB(%d)\n", udl_ctx.orphane_fb[i]);
      _drmModeRmFB(udl_ctx.fd, udl_ctx.orphane_fb[i]);
      udl_ctx.orphane_fb[i] = 0;
    }
  }
  pthread_mutex_unlock(&udl_ctx.mutex);
}

static void udl_record_orphane_fb(uint32_t fb_id)
{
  int i;

  pthread_mutex_lock(&udl_ctx.mutex);
  for (i = 0; i < ARRAY_SIZE(udl_ctx.orphane_fb); i++) {
    if (!udl_ctx.orphane_fb[i]) {
      udl_ctx.orphane_fb[i] = fb_id;
      break;
    }
  }
  pthread_mutex_unlock(&udl_ctx.mutex);

  udl_cleanup_orphane_fb();
}

drmModeResPtr drmModeGetResources(int fd)
{
  drmModeResPtr res;

  if (udl_is_udl(fd)) {
    if (udl_ctx.udl_flags & UDL_FLAG_HIDDEN)
      return NULL;

    return _drmModeGetResources(fd);
  }

  res = _drmModeGetResources(fd);
  if (!res)
    return NULL;

  if (!udl_update_status()) {
    /* Add fake CRTC */
    if (udl_ctx.udl_flags & UDL_FLAG_FORCE_ON)
      UDL_ADD_RES(res, crtcs, UDL_CRTC_ID);

    return res;
  }

  UDL_ADD_RES(res, crtcs, UDL_CRTC_ID);
  UDL_ADD_RES(res, connectors, WRAP_UDL_ID(udl_ctx.connector_id));
  UDL_ADD_RES(res, encoders, WRAP_UDL_ID(udl_ctx.encoder_id));
  return res;
}

drmModeFBPtr drmModeGetFB(int fd, uint32_t fb_id)
{
  return _drmModeGetFB(fd, PRIMARY_FB(fb_id));
}

#ifdef HAS_DRM_MODE_FB2
drmModeFB2Ptr drmModeGetFB2(int fd, uint32_t fb_id)
{
  return _drmModeGetFB2(fd, PRIMARY_FB(fb_id));
}
#endif

static uint32_t udl_import_handle(int fd, uint32_t handle,
                                  uint32_t width, uint32_t height,
                                  uint32_t stride, uint32_t format)
{
  uint32_t handles[4] = { 0, };
  uint32_t strides[4] = { 0, };
  uint32_t offsets[4] = { 0, };
  uint32_t fb_id;
  int dma_fd, ret;

  ret = drmPrimeHandleToFD(fd, handle, DRM_CLOEXEC | DRM_RDWR, &dma_fd);
  if (ret < 0)
    return 0;

  ret = drmPrimeFDToHandle(udl_ctx.fd, dma_fd, &handle);
  close(dma_fd);
  if (ret < 0)
    return 0;

  handles[0] = handle;
  strides[0] = stride;
  _drmModeAddFB2(udl_ctx.fd, width, height, format, handles, strides, offsets,
                 &fb_id, 0);
  drmCloseBufferHandle(udl_ctx.fd, handle);

  return fb_id;
}

static bool udl_format_supported(uint32_t format)
{
  return format == DRM_FORMAT_XRGB8888 || format == DRM_FORMAT_ARGB8888 ||
    format == DRM_FORMAT_RGB565;
}

int drmModeAddFB(int fd, uint32_t width, uint32_t height, uint8_t depth,
                 uint8_t bpp, uint32_t pitch, uint32_t bo_handle,
                 uint32_t *buf_id)
{
  uint32_t udl_fb_id;
  uint32_t format;
  int ret;

  ret = _drmModeAddFB(fd, width, height, depth, bpp, pitch, bo_handle, buf_id);
  if (ret < 0 || udl_is_udl(fd))
    return ret;

  DRM_DEBUG("add FB(%d)\n", *buf_id);

  if (!UDL_VALID())
    return 0;

  if (bpp == 16 && depth == 16)
    format = DRM_FORMAT_RGB565;
  else if (bpp == 32 && (depth == 32 || depth == 24))
    format = DRM_FORMAT_XRGB8888;
  else
    return 0;

  udl_fb_id = udl_import_handle(fd, bo_handle, width, height, pitch, format);
  if (!udl_fb_id)
    return 0;

  DRM_DEBUG("add UDL FB(%d)\n", udl_fb_id);

  *buf_id = WRAP_UDL_FB(*buf_id, udl_fb_id);
  return 0;
}

int drmModeAddFB2(int fd, uint32_t width, uint32_t height,
                  uint32_t pixel_format, const uint32_t bo_handles[4],
                  const uint32_t pitches[4], const uint32_t offsets[4],
                  uint32_t *buf_id, uint32_t flags)
{
  uint32_t udl_fb_id;
  int ret;

  ret = _drmModeAddFB2(fd, width, height, pixel_format, bo_handles,
                       pitches, offsets, buf_id, flags);
  if (ret < 0 || udl_is_udl(fd))
    return ret;

  DRM_DEBUG("add FB(%d)\n", *buf_id);

  if (!UDL_VALID())
    return 0;

  if (udl_format_supported(pixel_format))
    return 0;

  /* UDL only supports single-plane */
  udl_fb_id = udl_import_handle(fd, bo_handles[0], width, height,
                                pitches[0], pixel_format);
  if (!udl_fb_id)
    return 0;

  DRM_DEBUG("add UDL FB(%d)\n", udl_fb_id);

  *buf_id = WRAP_UDL_FB(*buf_id, udl_fb_id);
  return 0;
}

int drmModeAddFB2WithModifiers(int fd, uint32_t width, uint32_t height,
                               uint32_t pixel_format, const uint32_t bo_handles[4],
                               const uint32_t pitches[4], const uint32_t offsets[4],
                               const uint64_t modifier[4], uint32_t *buf_id,
                               uint32_t flags)
{
  int i;

  for (i = 0; i < 4; i++) {
    if (modifier[i] || modifier[i] != DRM_FORMAT_MOD_INVALID)
      return _drmModeAddFB2WithModifiers(fd, width, height, pixel_format,
                                         bo_handles, pitches, offsets, modifier,
                                         buf_id, flags);
  }

  return drmModeAddFB2(fd, width, height, pixel_format, bo_handles,
                       pitches, offsets, buf_id, flags);
}

int drmModeRmFB(int fd, uint32_t fb_id)
{
  uint32_t udl_fb_id = UDL_FB(fb_id);
  int ret;

  fb_id = PRIMARY_FB(fb_id);

  DRM_DEBUG("rm FB(%d)\n", fb_id);
  ret = _drmModeRmFB(fd, PRIMARY_FB(fb_id));

  if (udl_fb_id && UDL_VALID())
    udl_record_orphane_fb(udl_fb_id);

  return ret;
}

static int udl_dirty_current_fb(drmModeClipPtr clips, uint32_t num_clips)
{
  uint32_t fb_id;

  if (!UDL_VALID()) {
    DRM_ERROR("disconnected\n");
    return -ENODEV;
  }

  /* Only support single dirty rect */
  if (num_clips != 1)
    return -EINVAL;

  pthread_mutex_lock(&udl_ctx.mutex);
  if (udl_ctx.request.valid) {
    /* Should not overwrite old request */
    pthread_mutex_unlock(&udl_ctx.mutex);
    return -EAGAIN;
  }

  if (udl_ctx.process_fb_id) {
    fb_id = udl_ctx.process_fb_id;
  } else if (udl_ctx.curr_fb_id) {
    fb_id = udl_ctx.curr_fb_id;
  } else {
    /* No current FB */
    pthread_mutex_unlock(&udl_ctx.mutex);
    return -EINVAL;
  }

  DRM_DEBUG("request dirty FB(%d) with (%d,%d)(%dx%d)\n",
            fb_id, clips->x1, clips->y1,
            clips->x2 - clips->x1, clips->y2 - clips->y1);

  udl_ctx.request.clip = clips[0];
  udl_ctx.request.fb_id = fb_id;

  udl_ctx.request.valid = true;
  pthread_cond_signal(&udl_ctx.cond);
  pthread_mutex_unlock(&udl_ctx.mutex);

  return 0;
}

int drmModeDirtyFB(int fd, uint32_t fb_id,
                   drmModeClipPtr clips, uint32_t num_clips)
{
  uint32_t udl_fb_id = UDL_FB(fb_id);
  int ret = 0;

  fb_id = PRIMARY_FB(fb_id);

  if (udl_ctx.dirtyfb_mode == DIRTYFB_MODE_NONE)
    return -ENOSYS;

  if (udl_ctx.dirtyfb_mode == DIRTYFB_MODE_FAKE)
    return 0;

  /* HACK: Using FB(0) to update current FB */
  if (!udl_fb_id && !fb_id)
    return udl_dirty_current_fb(clips, num_clips);

  if (udl_fb_id)
    ret = _drmModeDirtyFB(udl_ctx.fd, udl_fb_id, clips, num_clips);

  if (udl_ctx.dirtyfb_mode == DIRTYFB_MODE_UDL_ONLY || !fb_id)
    return ret;

  return _drmModeDirtyFB(fd, fb_id, clips, num_clips);
}

drmModeCrtcPtr drmModeGetCrtc(int fd, uint32_t crtc_id)
{
  drmModeCrtcPtr crtc;

  if (!ID_IS_UDL(crtc_id))
    return _drmModeGetCrtc(fd, crtc_id);

  if (crtc_id != UDL_CRTC_ID) {
    DRM_ERROR("wrong CRTC id: %d\n", crtc_id);
    return NULL;
  }

  if (!udl_update_status()) {
    if (!(udl_ctx.udl_flags & UDL_FLAG_FORCE_ON)) {
      DRM_ERROR("disconnected\n");
      return NULL;
    }

    /* Alloc fake CRTC */
    crtc = calloc(1, sizeof(*crtc));
  } else {
    crtc = _drmModeGetCrtc(udl_ctx.fd, udl_ctx.crtc_id);
  }

  if (!crtc)
    return NULL;

  if (crtc->buffer_id)
    crtc->buffer_id = WRAP_UDL_FB(0, crtc->buffer_id);

  crtc->crtc_id = UDL_CRTC_ID;
  return crtc;
}

/**
 * Import primary DRM's FB to UDL
 * NOTE:
 * Using drmModeGetFB is dangerous, it would create extra handle and
 * might confuse the DRM GEM.
 */
static uint32_t udl_import_fb(int fd, uint32_t fb_id)
{
  drmModeFB2Ptr fb;
  uint32_t import_fb_id;
  int i;

  if (!fb_id)
    return 0;

  DRM_DEBUG("importing FB(%d)\n", fb_id);

  import_fb_id = fb_id;
  fb_id = 0;

  fb = _drmModeGetFB2(fd, import_fb_id);
  if (!fb)
    return 0;

  if (!udl_format_supported(fb->pixel_format))
    goto out;

  /* UDL only supports single-plane */
  fb_id = udl_import_handle(fd, fb->handles[0], fb->width, fb->height,
                            fb->pitches[0], fb->pixel_format);
  if (!fb_id)
    goto out;

  DRM_DEBUG("import FB(%d) -> FB(%d)\n", import_fb_id, fb_id);
out:
  for (i = 0; i < 4; i++) {
    if (fb->handles[i])
      drmCloseBufferHandle(fd, fb->handles[i]);
  }

  drmModeFreeFB2(fb);
  return fb_id;
}

int drmModeSetCrtc(int fd, uint32_t crtc_id, uint32_t fb_id,
                   uint32_t x, uint32_t y, uint32_t *connectors, int count,
                   drmModeModeInfoPtr mode)
{
  uint32_t udl_fb_id = UDL_FB(fb_id);
  int i, ret;

  fb_id = PRIMARY_FB(fb_id);

  if (!ID_IS_UDL(crtc_id))
    return _drmModeSetCrtc(fd, crtc_id, fb_id, x, y, connectors, count, mode);

  if (crtc_id != UDL_CRTC_ID) {
    DRM_ERROR("wrong CRTC id: %d\n", crtc_id);
    return -EINVAL;
  }

  if (!udl_update_status()) {
    DRM_ERROR("disconnected\n");
    return -ENODEV;
  }

  for (i = 0; i < count; i++)
    connectors[i] = UNWRAP_UDL_ID(connectors[i]);

  /* Convert FB for UDL */
  if (udl_fb_id) {
    fb_id = udl_fb_id;
  } else if (fb_id) {
    fb_id = udl_import_fb(fd, fb_id);
    if (!fb_id) {
      DRM_ERROR("failed to import FB\n");
      return -EINVAL;
    }
  }

  pthread_mutex_lock(&udl_ctx.mutex);
  DRM_DEBUG("set FB(%d) on CRTC(%d) to (%d,%d)\n",
            fb_id, udl_ctx.crtc_id, x, y);
  ret = _drmModeSetCrtc(udl_ctx.fd, udl_ctx.crtc_id, fb_id,
                        x, y, connectors, count, mode);
  if (!ret) {
    udl_ctx.curr_fb_id = fb_id;
    if (mode)
      udl_ctx.mode = *mode;
  }

  /* Drop pending request */
  memclear(udl_ctx.request);
  pthread_mutex_unlock(&udl_ctx.mutex);

  if (!udl_fb_id)
    udl_record_orphane_fb(fb_id);

  return ret;
}

static int udl_get_count_crtcs(int fd)
{
  drmModeResPtr res;
  int count_crtcs;

  res = _drmModeGetResources(fd);
  if (!res)
    return 0;

  count_crtcs = res->count_crtcs;
  drmModeFreeResources(res);
  return count_crtcs;
}

drmModeEncoderPtr drmModeGetEncoder(int fd, uint32_t encoder_id)
{
  drmModeEncoderPtr encoder;
  int count_crtcs;

  if (!ID_IS_UDL(encoder_id))
    return _drmModeGetEncoder(fd, encoder_id);

  if (!udl_update_status()) {
    DRM_ERROR("disconnected\n");
    return NULL;
  }

  encoder = _drmModeGetEncoder(udl_ctx.fd, UNWRAP_UDL_ID(encoder_id));
  if (!encoder)
    return NULL;

  encoder->encoder_id = WRAP_UDL_ID(encoder->encoder_id);
  encoder->crtc_id = UDL_CRTC_ID;

  count_crtcs = udl_get_count_crtcs(fd);
  encoder->possible_crtcs <<= count_crtcs;
  encoder->possible_clones <<= count_crtcs;
  return encoder;
}

static drmModeConnectorPtr udl_fixup_connector(drmModeConnectorPtr connector)
{
  int i;

  if (!connector)
    return NULL;

  connector->connector_id = WRAP_UDL_ID(connector->connector_id);
  connector->encoder_id = WRAP_UDL_ID(connector->encoder_id);

  for (i = 0; i < connector->count_props; i++)
    connector->props[i] = WRAP_UDL_ID(connector->props[i]);

  for (i = 0; i < connector->count_encoders; i++)
    connector->encoders[i] = WRAP_UDL_ID(connector->encoders[i]);

  return connector;
}

drmModeConnectorPtr drmModeGetConnector(int fd, uint32_t connector_id)
{
  drmModeConnectorPtr connector;

  if (!ID_IS_UDL(connector_id))
    return _drmModeGetConnector(fd, connector_id);

  if (!udl_update_status()) {
    DRM_ERROR("disconnected\n");
    return NULL;
  }

  connector = _drmModeGetConnector(udl_ctx.fd, UNWRAP_UDL_ID(connector_id));
  return udl_fixup_connector(connector);
}

drmModeConnectorPtr drmModeGetConnectorCurrent(int fd, uint32_t connector_id)
{
  drmModeConnectorPtr connector;

  if (!ID_IS_UDL(connector_id))
    return _drmModeGetConnectorCurrent(fd, connector_id);

  if (!udl_update_status()) {
    DRM_ERROR("disconnected\n");
    return NULL;
  }

  connector =
    _drmModeGetConnectorCurrent(udl_ctx.fd, UNWRAP_UDL_ID(connector_id));
  return udl_fixup_connector(connector);
}

int drmModeAttachMode(int fd, uint32_t connector_id,
                      drmModeModeInfoPtr mode_info)
{
  if (!ID_IS_UDL(connector_id))
    return _drmModeAttachMode(fd, connector_id, mode_info);

  if (!udl_update_status()) {
    DRM_ERROR("disconnected\n");
    return -ENODEV;
  }

  return _drmModeAttachMode(udl_ctx.fd, UNWRAP_UDL_ID(connector_id), mode_info);
}

int drmModeDetachMode(int fd, uint32_t connector_id,
                      drmModeModeInfoPtr mode_info)
{
  if (!ID_IS_UDL(connector_id))
    return _drmModeDetachMode(fd, connector_id, mode_info);

  if (!udl_update_status()) {
    DRM_ERROR("disconnected\n");
    return -ENODEV;
  }

  return _drmModeDetachMode(udl_ctx.fd, UNWRAP_UDL_ID(connector_id), mode_info);
}

drmModePropertyPtr drmModeGetProperty(int fd, uint32_t property_id)
{
  drmModePropertyPtr prop;
  int i;

  if (!ID_IS_UDL(property_id))
    return _drmModeGetProperty(fd, property_id);

  if (!udl_update_status()) {
    DRM_ERROR("disconnected\n");
    return NULL;
  }

  prop = _drmModeGetProperty(udl_ctx.fd, UNWRAP_UDL_ID(property_id));
  if (!prop)
    return NULL;

  prop->prop_id = WRAP_UDL_ID(prop->prop_id);

  for (i = 0; i < prop->count_blobs; i++)
    prop->blob_ids[i] = WRAP_UDL_ID(prop->blob_ids[i]);

  return prop;
}

drmModePropertyBlobPtr drmModeGetPropertyBlob(int fd, uint32_t blob_id)
{
  drmModePropertyBlobPtr blob;

  if (!ID_IS_UDL(blob_id))
    return _drmModeGetPropertyBlob(fd, blob_id);

  if (!udl_update_status()) {
    DRM_ERROR("disconnected\n");
    return NULL;
  }

  blob = _drmModeGetPropertyBlob(udl_ctx.fd, UNWRAP_UDL_ID(blob_id));
  if (!blob)
    return NULL;

  blob->id = WRAP_UDL_ID(blob->id);
  return blob;
}

int drmModeConnectorSetProperty(int fd, uint32_t connector_id,
                                uint32_t property_id, uint64_t value)
{
  if (!ID_IS_UDL(connector_id))
    return _drmModeConnectorSetProperty(fd, connector_id, property_id, value);

  if (!udl_update_status()) {
    DRM_ERROR("disconnected\n");
    return -ENODEV;
  }

  return _drmModeConnectorSetProperty(udl_ctx.fd, UNWRAP_UDL_ID(connector_id),
                                      UNWRAP_UDL_ID(property_id), value);
}

int drmModeCrtcSetGamma(int fd, uint32_t crtc_id, uint32_t size,
                        uint16_t *red, uint16_t *green, uint16_t *blue)
{
  if (!ID_IS_UDL(crtc_id))
    return _drmModeCrtcSetGamma(fd, crtc_id, size, red, green, blue);

  if (crtc_id != UDL_CRTC_ID) {
    DRM_ERROR("wrong CRTC id: %d\n", crtc_id);
    return -EINVAL;
  }

  if (!udl_update_status()) {
    DRM_ERROR("disconnected\n");
    return -ENODEV;
  }

  return _drmModeCrtcSetGamma(udl_ctx.fd, udl_ctx.crtc_id,
                              size, red, green, blue);
}

int drmModeCrtcGetGamma(int fd, uint32_t crtc_id, uint32_t size,
                        uint16_t *red, uint16_t *green, uint16_t *blue)
{
  if (!ID_IS_UDL(crtc_id))
    return _drmModeCrtcGetGamma(fd, crtc_id, size, red, green, blue);

  if (crtc_id != UDL_CRTC_ID) {
    DRM_ERROR("wrong CRTC id: %d\n", crtc_id);
    return -EINVAL;
  }

  if (!udl_update_status()) {
    DRM_ERROR("disconnected\n");
    return -ENODEV;
  }

  return _drmModeCrtcGetGamma(udl_ctx.fd, udl_ctx.crtc_id,
                              size, red, green, blue);
}

int drmModePageFlip(int fd, uint32_t crtc_id, uint32_t fb_id,
                    uint32_t flags, void *user_data)
{
  if (!ID_IS_UDL(crtc_id))
    return _drmModePageFlip(fd, crtc_id, PRIMARY_FB(fb_id), flags, user_data);

  errno = ENOSYS;
  return -errno;
}

int drmModePageFlipTarget(int fd, uint32_t crtc_id, uint32_t fb_id,
                          uint32_t flags, void *user_data,
                          uint32_t target_vblank)
{
  if (!ID_IS_UDL(crtc_id))
    return _drmModePageFlipTarget(fd, crtc_id, PRIMARY_FB(fb_id), flags,
                                  user_data, target_vblank);

  /* HACK: Using FB(0) to query process state */
  if (!fb_id && !udl_ctx.process_fb_id && !udl_ctx.request.valid)
    return 0;

  errno = ENOSYS;
  return -errno;
}

drmModePlaneResPtr drmModeGetPlaneResources(int fd)
{
  drmModePlaneResPtr pres;

  if (udl_is_udl(fd)) {
    if (udl_ctx.udl_flags & UDL_FLAG_HIDDEN) {
      DRM_ERROR("disconnected\n");
      return NULL;
    }

    return _drmModeGetPlaneResources(fd);
  }

  pres = _drmModeGetPlaneResources(fd);
  if (!pres)
    return NULL;

  if (!udl_update_status()) {
    /* Add fake plane */
    if (udl_ctx.udl_flags & UDL_FLAG_FORCE_ON)
      UDL_ADD_RES(pres, planes, UDL_PLANE_ID);
  } else {
    UDL_ADD_RES(pres, planes, UDL_PLANE_ID);
  }

  return pres;
}

drmModePlanePtr drmModeGetPlane(int fd, uint32_t plane_id)
{
  drmModePlanePtr plane;
  int count_crtcs;

  if (!ID_IS_UDL(plane_id))
    return _drmModeGetPlane(fd, plane_id);

  if (plane_id != UDL_PLANE_ID) {
    DRM_ERROR("wrong plane id: %d\n", plane_id);
    return NULL;
  }

  if (!udl_update_status()) {
    if (!(udl_ctx.udl_flags & UDL_FLAG_FORCE_ON)) {
      DRM_ERROR("disconnected\n");
      return NULL;
    }

    /* Alloc fake plane */
    plane = calloc(1, sizeof(*plane));
    plane->possible_crtcs = 1;
  } else {
    plane = _drmModeGetPlane(udl_ctx.fd, udl_ctx.plane_id);
  }

  if (!plane)
    return NULL;

  plane->plane_id = UDL_PLANE_ID;

  if (plane->crtc_id)
    plane->crtc_id = UDL_CRTC_ID;

  if (plane->fb_id)
    plane->fb_id = WRAP_UDL_FB(0, plane->fb_id);

  count_crtcs = udl_get_count_crtcs(fd);
  plane->possible_crtcs <<= count_crtcs;
  return plane;
}

static void *udl_thread_fn(__attribute__((unused)) void *data)
{
  uint32_t crtc_id, connector_id, plane_id, fb_id, flags;
  uint32_t crtc_x, crtc_y, crtc_w, crtc_h, src_x, src_y, src_w, src_h;
  drmModeModeInfo mode;
  drmModeClip clip;
  int fd, ret;

  while (1) {
    pthread_mutex_lock(&udl_ctx.mutex);
    while (!UDL_VALID() || !udl_ctx.request.valid)
      pthread_cond_wait(&udl_ctx.cond, &udl_ctx.mutex);

    fd = udl_ctx.fd;
    crtc_id = udl_ctx.crtc_id;
    connector_id = udl_ctx.connector_id;
    plane_id = udl_ctx.plane_id;
    mode = udl_ctx.mode;

    clip = udl_ctx.request.clip;
    fb_id = udl_ctx.request.fb_id;
    flags = udl_ctx.request.flags;
    crtc_x = udl_ctx.request.crtc_x;
    crtc_y = udl_ctx.request.crtc_y;
    crtc_w = udl_ctx.request.crtc_w;
    crtc_h = udl_ctx.request.crtc_h;
    src_x = udl_ctx.request.src_x;
    src_y = udl_ctx.request.src_y;
    src_w = udl_ctx.request.src_w;
    src_h = udl_ctx.request.src_h;
    memclear(udl_ctx.request);

    udl_ctx.process_fb_id = fb_id;
    pthread_mutex_unlock(&udl_ctx.mutex);

    if (fb_id == udl_ctx.curr_fb_id && clip.x2 && clip.y2) {
      DRM_DEBUG("dirty FB(%d) with (%d,%d)(%dx%d)\n",
                fb_id, clip.x1, clip.y1, clip.x2 - clip.x1, clip.y2 - clip.y1);

      ret = _drmModeDirtyFB(fd, fb_id, &clip, 1);
    } else if (udl_ctx.force_fullscreen) {
      DRM_DEBUG("set FB(%d) on CRTC(%d) to (%d,%d)\n",
                fb_id, crtc_id, crtc_x, crtc_y);
      ret = _drmModeSetCrtc(fd, crtc_id, fb_id, crtc_x, crtc_y,
                            &connector_id, 1, &mode);
    } else {
      DRM_DEBUG("set FB(%d) on plane(%d/%d) from "
                "(%d,%d)(%dx%d) to (%d,%d)(%dx%d)\n",
                fb_id, plane_id, crtc_id,
                src_x >> 16, src_y >> 16, src_w >> 16, src_h >> 16,
                crtc_x, crtc_y, crtc_w, crtc_h);

      ret = _drmModeSetPlane(fd, plane_id, crtc_id, fb_id, flags,
                             crtc_x, crtc_y, crtc_w, crtc_h,
                             src_x, src_y, src_w, src_h);
    }
    if (ret < 0) {
      DRM_ERROR("failed to process FB(%d): %d\n", fb_id, ret);
    } else {
      DRM_DEBUG("finish processing FB(%d)\n", fb_id);
    }

    pthread_mutex_lock(&udl_ctx.mutex);
    if (!ret)
      udl_ctx.curr_fb_id = fb_id;

    udl_ctx.process_fb_id = 0;
    pthread_mutex_unlock(&udl_ctx.mutex);

    udl_cleanup_orphane_fb();
  }

  return NULL;
}

int drmModeSetPlane(int fd, uint32_t plane_id, uint32_t crtc_id,
                    uint32_t fb_id, uint32_t flags,
                    int32_t crtc_x, int32_t crtc_y,
                    uint32_t crtc_w, uint32_t crtc_h,
                    uint32_t src_x, uint32_t src_y,
                    uint32_t src_w, uint32_t src_h)
{
  uint32_t udl_fb_id = UDL_FB(fb_id);

  fb_id = PRIMARY_FB(fb_id);

  if (!ID_IS_UDL(plane_id))
    return _drmModeSetPlane(fd, plane_id, crtc_id, fb_id, flags,
                            crtc_x, crtc_y, crtc_w, crtc_h,
                            src_x, src_y, src_w, src_h);

  if (!UDL_VALID()) {
    DRM_ERROR("disconnected\n");
    return -ENODEV;
  }

  if (crtc_id != UDL_CRTC_ID) {
    DRM_ERROR("wrong CRTC id: %d\n", plane_id);
    return -EINVAL;
  }

  if (plane_id != UDL_PLANE_ID) {
    DRM_ERROR("wrong plane id: %d\n", plane_id);
    return -EINVAL;
  }

  /* Convert FB for UDL */
  if (udl_fb_id) {
    fb_id = udl_fb_id;
  } else if (fb_id) {
    fb_id = udl_import_fb(fd, fb_id);
    if (!fb_id) {
      DRM_ERROR("failed to import FB\n");
      return -EINVAL;
    }
  }

  pthread_mutex_lock(&udl_ctx.mutex);
  DRM_DEBUG("request set FB(%d) from (%d,%d)(%dx%d) to (%d,%d)(%dx%d)\n",
            fb_id, src_x >> 16, src_y >> 16, src_w >> 16, src_h >> 16,
            crtc_x, crtc_y, crtc_w, crtc_h);

  udl_ctx.request.fb_id = fb_id;
  udl_ctx.request.flags = flags;
  udl_ctx.request.crtc_x = crtc_x;
  udl_ctx.request.crtc_y = crtc_y;
  udl_ctx.request.crtc_w = crtc_w;
  udl_ctx.request.crtc_h = crtc_h;
  udl_ctx.request.src_x = src_x;
  udl_ctx.request.src_y = src_y;
  udl_ctx.request.src_w = src_w;
  udl_ctx.request.src_h = src_h;

  udl_ctx.request.valid = true;
  pthread_cond_signal(&udl_ctx.cond);
  pthread_mutex_unlock(&udl_ctx.mutex);

  if (!udl_fb_id)
    udl_record_orphane_fb(fb_id);

  return 0;
}

drmModeObjectPropertiesPtr drmModeObjectGetProperties(int fd,
                                                      uint32_t object_id,
                                                      uint32_t object_type)
{
  drmModeObjectPropertiesPtr props;
  int i;

  if (!ID_IS_UDL(object_id))
    return _drmModeObjectGetProperties(fd, object_id, object_type);

  if (!udl_update_status()) {
    if (!(udl_ctx.udl_flags & UDL_FLAG_FORCE_ON)) {
      DRM_ERROR("disconnected\n");
      return NULL;
    }

    /* Return empty props */
    return calloc(1, sizeof(*props));
  }

  if (object_type == DRM_MODE_OBJECT_CRTC) {
    if (object_id != UDL_CRTC_ID) {
      DRM_ERROR("wrong CRTC id: %d\n", object_id);
      return NULL;
    }

    object_id = udl_ctx.crtc_id;
  } else if (object_type == DRM_MODE_OBJECT_PLANE) {
    if (object_id != UDL_PLANE_ID) {
      DRM_ERROR("wrong plane id: %d\n", object_id);
      return NULL;
    }

    object_id = udl_ctx.plane_id;
  } else {
    object_id = UNWRAP_UDL_ID(object_id);
  }

  props = _drmModeObjectGetProperties(udl_ctx.fd, object_id, object_type);
  if (!props)
    return NULL;

  for (i = 0; i < (int)props->count_props; i++)
    props->props[i] = WRAP_UDL_ID(props->props[i]);

  return props;
}

int drmModeObjectSetProperty(int fd, uint32_t object_id,
                             uint32_t object_type, uint32_t property_id,
                             uint64_t value)
{
  if (!ID_IS_UDL(object_id))
    return _drmModeObjectSetProperty(fd, object_id, object_type,
                                     property_id, value);

  if (!udl_update_status()) {
    DRM_ERROR("disconnected\n");
    return -ENODEV;
  }

  if (object_type == DRM_MODE_OBJECT_CRTC) {
    if (object_id != UDL_CRTC_ID) {
      DRM_ERROR("wrong CRTC id: %d\n", object_id);
      return -EINVAL;
    }

    object_id = udl_ctx.crtc_id;
  } else if (object_type == DRM_MODE_OBJECT_PLANE) {
    if (object_id != UDL_PLANE_ID) {
      DRM_ERROR("wrong plane id: %d\n", object_id);
      return -EINVAL;
    }

    object_id = udl_ctx.plane_id;
  } else {
    object_id = UNWRAP_UDL_ID(object_id);
  }

  return _drmModeObjectSetProperty(udl_ctx.fd, object_id, object_type,
                                   UNWRAP_UDL_ID(property_id), value);
}
