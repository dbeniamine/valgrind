include $(top_srcdir)/Makefile.tool.am

EXTRA_DIST = docs/hi-manual.xml

#----------------------------------------------------------------------------
# Headers, flags
#----------------------------------------------------------------------------

pkginclude_HEADERS = heapinfo.h

noinst_HEADERS = hi_list.c\
				 hi_list.h \
				 hi_array.h
#----------------------------------------------------------------------------
# heapinfo-<platform>
#----------------------------------------------------------------------------

noinst_PROGRAMS  = heapinfo-@VGCONF_ARCH_PRI@-@VGCONF_OS@
if VGCONF_HAVE_PLATFORM_SEC
noinst_PROGRAMS += heapinfo-@VGCONF_ARCH_SEC@-@VGCONF_OS@
endif

HEAPINFO_SOURCES_COMMON = \
					hi_array.c\
					hi_list.c \
					hi_main.c 

heapinfo_@VGCONF_ARCH_PRI@_@VGCONF_OS@_SOURCES      = \
	$(HEAPINFO_SOURCES_COMMON)
heapinfo_@VGCONF_ARCH_PRI@_@VGCONF_OS@_CPPFLAGS     = \
	$(AM_CPPFLAGS_@VGCONF_PLATFORM_PRI_CAPS@)
heapinfo_@VGCONF_ARCH_PRI@_@VGCONF_OS@_CFLAGS       = \
	$(AM_CFLAGS_@VGCONF_PLATFORM_PRI_CAPS@)
heapinfo_@VGCONF_ARCH_PRI@_@VGCONF_OS@_DEPENDENCIES = \
	$(TOOL_DEPENDENCIES_@VGCONF_PLATFORM_PRI_CAPS@)
heapinfo_@VGCONF_ARCH_PRI@_@VGCONF_OS@_LDADD        = \
	$(TOOL_LDADD_@VGCONF_PLATFORM_PRI_CAPS@)
heapinfo_@VGCONF_ARCH_PRI@_@VGCONF_OS@_LDFLAGS      = \
	$(TOOL_LDFLAGS_@VGCONF_PLATFORM_PRI_CAPS@)
heapinfo_@VGCONF_ARCH_PRI@_@VGCONF_OS@_LINK = \
	$(top_builddir)/coregrind/link_tool_exe_@VGCONF_OS@ \
	@VALT_LOAD_ADDRESS_PRI@ \
	$(LINK) \
	$(heapinfo_@VGCONF_ARCH_PRI@_@VGCONF_OS@_CFLAGS) \
	$(heapinfo_@VGCONF_ARCH_PRI@_@VGCONF_OS@_LDFLAGS)

if VGCONF_HAVE_PLATFORM_SEC
heapinfo_@VGCONF_ARCH_SEC@_@VGCONF_OS@_SOURCES      = \
	$(HEAPINFO_SOURCES_COMMON)
heapinfo_@VGCONF_ARCH_SEC@_@VGCONF_OS@_CPPFLAGS     = \
	$(AM_CPPFLAGS_@VGCONF_PLATFORM_SEC_CAPS@)
heapinfo_@VGCONF_ARCH_SEC@_@VGCONF_OS@_CFLAGS       = \
	$(AM_CFLAGS_@VGCONF_PLATFORM_SEC_CAPS@)
heapinfo_@VGCONF_ARCH_SEC@_@VGCONF_OS@_DEPENDENCIES = \
	$(TOOL_DEPENDENCIES_@VGCONF_PLATFORM_SEC_CAPS@)
heapinfo_@VGCONF_ARCH_SEC@_@VGCONF_OS@_LDADD        = \
	$(TOOL_LDADD_@VGCONF_PLATFORM_SEC_CAPS@)
heapinfo_@VGCONF_ARCH_SEC@_@VGCONF_OS@_LDFLAGS      = \
	$(TOOL_LDFLAGS_@VGCONF_PLATFORM_SEC_CAPS@)
heapinfo_@VGCONF_ARCH_SEC@_@VGCONF_OS@_LINK = \
	$(top_builddir)/coregrind/link_tool_exe_@VGCONF_OS@ \
	@VALT_LOAD_ADDRESS_SEC@ \
	$(LINK) \
	$(heapinfo_@VGCONF_ARCH_SEC@_@VGCONF_OS@_CFLAGS) \
	$(heapinfo_@VGCONF_ARCH_SEC@_@VGCONF_OS@_LDFLAGS)
endif


#----------------------------------------------------------------------------
# vgpreload_heapinfo-<platform>.so
#----------------------------------------------------------------------------

noinst_PROGRAMS += vgpreload_heapinfo-@VGCONF_ARCH_PRI@-@VGCONF_OS@.so
if VGCONF_HAVE_PLATFORM_SEC
noinst_PROGRAMS += vgpreload_heapinfo-@VGCONF_ARCH_SEC@-@VGCONF_OS@.so
endif

if VGCONF_OS_IS_DARWIN
noinst_DSYMS = $(noinst_PROGRAMS)
endif

vgpreload_heapinfo_@VGCONF_ARCH_PRI@_@VGCONF_OS@_so_SOURCES      = 
vgpreload_heapinfo_@VGCONF_ARCH_PRI@_@VGCONF_OS@_so_CPPFLAGS     = \
	$(AM_CPPFLAGS_@VGCONF_PLATFORM_PRI_CAPS@)
vgpreload_heapinfo_@VGCONF_ARCH_PRI@_@VGCONF_OS@_so_CFLAGS       = \
	$(AM_CFLAGS_@VGCONF_PLATFORM_PRI_CAPS@) $(AM_CFLAGS_PIC)
vgpreload_heapinfo_@VGCONF_ARCH_PRI@_@VGCONF_OS@_so_DEPENDENCIES = \
	$(LIBREPLACEMALLOC_@VGCONF_PLATFORM_PRI_CAPS@)
vgpreload_heapinfo_@VGCONF_ARCH_PRI@_@VGCONF_OS@_so_LDFLAGS      = \
	$(PRELOAD_LDFLAGS_@VGCONF_PLATFORM_PRI_CAPS@) \
	$(LIBREPLACEMALLOC_LDFLAGS_@VGCONF_PLATFORM_PRI_CAPS@)

if VGCONF_HAVE_PLATFORM_SEC
vgpreload_heapinfo_@VGCONF_ARCH_SEC@_@VGCONF_OS@_so_SOURCES      = 
vgpreload_heapinfo_@VGCONF_ARCH_SEC@_@VGCONF_OS@_so_CPPFLAGS     = \
	$(AM_CPPFLAGS_@VGCONF_PLATFORM_SEC_CAPS@)
vgpreload_heapinfo_@VGCONF_ARCH_SEC@_@VGCONF_OS@_so_CFLAGS       = \
	$(AM_CFLAGS_@VGCONF_PLATFORM_SEC_CAPS@) $(AM_CFLAGS_PIC)
vgpreload_heapinfo_@VGCONF_ARCH_SEC@_@VGCONF_OS@_so_DEPENDENCIES = \
	$(LIBREPLACEMALLOC_@VGCONF_PLATFORM_SEC_CAPS@)
vgpreload_heapinfo_@VGCONF_ARCH_SEC@_@VGCONF_OS@_so_LDFLAGS      = \
	$(PRELOAD_LDFLAGS_@VGCONF_PLATFORM_SEC_CAPS@) \
	$(LIBREPLACEMALLOC_LDFLAGS_@VGCONF_PLATFORM_SEC_CAPS@)
endif

