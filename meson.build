project(
  'libdrm-udl',
  'c',
  version : '1.0.0',
  meson_version : '>=0.47.0',
  default_options: ['buildtype=release', 'warning_level=3'],
)

pkgconfig = import('pkgconfig')

cc = meson.get_compiler('c')

drm_dep = dependency('libdrm', version : '>= 2.4.0')
dl_dep = cc.find_library('dl', required : false)
threads_dep = dependency('threads')
udl_deps = [drm_dep, dl_dep, threads_dep]

udl_c_args = []
if cc.has_function('drmModeGetFB2', dependencies : drm_dep)
udl_c_args += ['-DHAS_DRM_MODE_FB2']
endif
if cc.has_function('drmCloseBufferHandle', dependencies : drm_dep)
udl_c_args += ['-DHAS_DRM_CLOSE_HANDLE']
endif

libdrm_udl = shared_library(
  'drm-udl',
  ['drm_udl.c'],
  c_args : udl_c_args,
  dependencies : udl_deps,
  version : meson.project_version(),
  install : true,
)

pkgconfig.generate(
  libdrm_udl,
  version : meson.project_version(),
  description : 'A hook of legacy DRM APIs to integrate UDL to primary DRM device.',
)

configure_file(
  input : 'drm-udl.conf.sample',
  output : 'drm-udl.conf',
  install_dir : get_option('sysconfdir'),
  copy : true,
)
