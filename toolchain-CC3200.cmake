### BEGIN CMAKE_TOOLCHAIN_FILE
# "Generic" is used when cross compiling �������ʹ��Generic
set(CMAKE_SYSTEM_NAME Generic)

# Set the EW installation root directory ����EW��װ·��
#(Avoid spaces in the path or you need to escape them)
set(EW_ROOT_DIR "F:/ti/IAR/arm")

# Compiler flags needed to compile for this CPU
# set(CPU_FLAGS "--cpu cortex-m4")

# Set up the CMake variables for compiler and assembler
# (The reason for both C and CXX variables is that CMake
# treats C and C++ tools individually)
set(CMAKE_C_COMPILER "${EW_ROOT_DIR}/bin/iccarm.exe" "${CPU_FLAGS} --dlib_config normal")
set(CMAKE_CXX_COMPILER "${EW_ROOT_DIR}/bin/iccarm.exe" "${CPU_FLAGS} --dlib_config normal")
set(CMAKE_ASM_COMPILER "${EW_ROOT_DIR}/bin/iasmarm.exe" "${CPU_FLAGS}")

# Set up the CMake variables for the linker
set(LINKER_SCRIPT "${EW_ROOT_DIR}/config/linker/TexasInstruments/cc3200.icf")
set(CMAKE_C_LINK_FLAGS "--semihosting --config ${LINKER_SCRIPT}")
set(CMAKE_CXX_LINK_FLAGS "--semihosting --config ${LINKER_SCRIPT}")
### END CMAKE_TOOLCHAIN_FILE