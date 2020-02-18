TEMPLATE = app
CONFIG += console c++17
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
        Crypto/Blowfish/Blowfish.cpp \
        Crypto/Gost/Gost.cpp \
        main.cpp

HEADERS += \
   Crypto/Blowfish/Blowfish.h \
   Crypto/Blowfish/BlowfishData.h \
   Crypto/Gost/Gost.h
