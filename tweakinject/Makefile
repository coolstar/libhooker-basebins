TARGET = iphone:latest:10.0
ARCHS = arm64 arm64e
include $(THEOS)/makefiles/common.mk

TWEAK_NAME = TweakInject
TweakInject_FILES = Tweak.x linksSymbol.c
TweakInject_USE_SUBSTRATE = 0
TweakInject_C_FLAGS = -fvisibility=hidden -I .

#TweakInject_LOGOS_DEFAULT_GENERATOR = internal

include $(THEOS_MAKE_PATH)/tweak.mk

after-install::
	install.exec "killall -9 SpringBoard"
