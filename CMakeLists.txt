cmake_minimum_required(VERSION 3.2)

#项目名
project(libeegdp)

# 1、指定库的目录变量
set(libeegdp_src src/ffrdp.c)
# 指定头文件搜索路径
include_directories("${PROJECT_SOURCE_DIR}/include")

# 2、添加库(对应的两个项目)
add_library( eegdp_shared SHARED ${libeegdp_src})
add_library( eegdp_static STATIC ${libeegdp_src})
#  按照一般的习惯，静态库名字跟动态库名字应该是一致的，只是扩展名不同；
# 即：静态库名为 libeegdp.a； 动态库名为libeegdp.so ；
# 所以，希望 "eegdp_static" 在输出时，不是"eegdp_static"，而是以"eegdp"的名字显示，故设置如下
# SET_TARGET_PROPERTIES (eegdp_static PROPERTIES OUTPUT_NAME "eegdp")

# 3、cmake在构建一个新的target时，会尝试清理掉其他使用这个名字的库，
# 因此，在构建libeegdp.a时，就会清理掉libeegdp.so.
# 为了回避这个问题，比如再次使用SET_TARGET_PROPERTIES定义 CLEAN_DIRECT_OUTPUT属性。
SET_TARGET_PROPERTIES (eegdp_static PROPERTIES CLEAN_DIRECT_OUTPUT 1)
SET_TARGET_PROPERTIES (eegdp_shared PROPERTIES CLEAN_DIRECT_OUTPUT 1)


# 4、按照规则，动态库是应该包含一个版本号的，
# VERSION指代动态库版本，SOVERSION指代API版本。
SET_TARGET_PROPERTIES (eegdp_static PROPERTIES VERSION 1.1 SOVERSION 1)
SET_TARGET_PROPERTIES (eegdp_shared PROPERTIES VERSION 1.1 SOVERSION 1)

# 添加连接库(socket)
IF (WIN32)
TARGET_LINK_LIBRARIES(eegdp_static Ws2_32.lib)
TARGET_LINK_LIBRARIES(eegdp_shared Ws2_32.lib)
TARGET_LINK_LIBRARIES(eegdp_static winmm.lib)
TARGET_LINK_LIBRARIES(eegdp_shared winmm.lib)
ADD_DEFINITIONS(-D WIN32)
ELSEIF(UNIX)
ELSE() #CC3200链接库
ADD_DEFINITIONS(-D CC3200)
include_directories("${PROJECT_SOURCE_DIR}/../../simplelink/include")
include_directories("${PROJECT_SOURCE_DIR}/../../driverlib")
TARGET_LINK_LIBRARIES(eegdp_static "${PROJECT_SOURCE_DIR}/../../simplelink/ewarm/OS/Exe/simplelink.a")
TARGET_LINK_LIBRARIES(eegdp_static "${PROJECT_SOURCE_DIR}/../../driverlib/ewarm/Release/Exe/driverlib.a")
ENDIF()

