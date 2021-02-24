cmake_minimum_required(VERSION 3.2)

#��Ŀ��
project(libeegdp)

# 1��ָ�����Ŀ¼����
set(libeegdp_src src/ffrdp.c)
# ָ��ͷ�ļ�����·��
include_directories("${PROJECT_SOURCE_DIR}/include")

# 2�����ӿ�(��Ӧ��������Ŀ)
add_library( eegdp_shared SHARED ${libeegdp_src})
add_library( eegdp_static STATIC ${libeegdp_src})
#  ����һ���ϰ�ߣ���̬�����ָ���̬������Ӧ����һ�µģ�ֻ����չ����ͬ��
# ������̬����Ϊ libeegdp.a�� ��̬����Ϊlibeegdp.so ��
# ���ԣ�ϣ�� "eegdp_static" �����ʱ������"eegdp_static"��������"eegdp"��������ʾ������������
# SET_TARGET_PROPERTIES (eegdp_static PROPERTIES OUTPUT_NAME "eegdp")

# 3��cmake�ڹ���һ���µ�targetʱ���᳢������������ʹ��������ֵĿ⣬
# ��ˣ��ڹ���libeegdp.aʱ���ͻ�������libeegdp.so.
# Ϊ�˻ر�������⣬�����ٴ�ʹ��SET_TARGET_PROPERTIES���� CLEAN_DIRECT_OUTPUT���ԡ�
SET_TARGET_PROPERTIES (eegdp_static PROPERTIES CLEAN_DIRECT_OUTPUT 1)
SET_TARGET_PROPERTIES (eegdp_shared PROPERTIES CLEAN_DIRECT_OUTPUT 1)


# 4�����չ��򣬶�̬����Ӧ�ð���һ���汾�ŵģ�
# VERSIONָ����̬��汾��SOVERSIONָ��API�汾��
SET_TARGET_PROPERTIES (eegdp_static PROPERTIES VERSION 1.1 SOVERSION 1)
SET_TARGET_PROPERTIES (eegdp_shared PROPERTIES VERSION 1.1 SOVERSION 1)

# �������ӿ�
IF (WIN32)
TARGET_LINK_LIBRARIES(eegdp_static Ws2_32.lib)
TARGET_LINK_LIBRARIES(eegdp_shared Ws2_32.lib)
TARGET_LINK_LIBRARIES(eegdp_static winmm.lib)
TARGET_LINK_LIBRARIES(eegdp_shared winmm.lib)
ADD_DEFINITIONS(-D WIN32)
ELSEIF(UNIX)
ELSE() #CC3200
ENDIF()
