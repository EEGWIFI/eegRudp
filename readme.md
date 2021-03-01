### eegRudp
eegRudp是一个跨平台（单片机/Linux/Windows）的基于 udp + arq + fec 的快速可靠协议
##### 原理分析
rto(Retransmission Timeout) 计算：
初始：
rtts = rttm;
rttd = rttm / 2;

迭代：
rtts = (1 - alpha) * rtts + alpha * rttm; // alpha = 1 / 8
rttd = (1 - beta ) * rttd + beta  * abs(rttm - rtts); // beta = 1 / 4

正常：
rto  = rtts + r * rttd;

超时：
rto  = 1.5 * rto;


帧定义：
data frame:
data_full  frame: 0x00 seq0 seq1 seq2 data ...
data_short frame: 0x01 seq0 seq1 seq2 data ...
data_fec2  frame: 0x02 seq0 seq1 seq2 data ... fec_seq0 fec_seq1
data_fec3  frame: 0x03 seq0 seq1 seq2 data ... fec_seq0 fec_seq1
data_fec4  frame: 0x04 seq0 seq1 seq2 data ... fec_seq0 fec_seq1
... ...
data_fec32 frame: 0x3E seq0 seq1 seq2 data ... fec_seq0 fec_seq1

ack   frame: 0x40 una0 una1 una2 mack0 mack1 mack2 rwnd
query frame: 0x41

data_full  frame 为不带 fec 的 data 长帧
data_short frame 为不带 fec 的 data 短帧
data_fecN 为每 N 帧带一个 fec 帧（N >= 2 && N <= 32）


协议特点：
选择重传、快速重传、非延迟 ACK、UNA + MACK、非退让流控、FEC 前向纠错


协议说明：
seq una 长度为 24bit，recv_win_size 为 16bit
ack 帧包含了 una, mack 和 rwnd size 信息
mack 24bit 是一个 bitmap, 包含了 una 之后，但又已经被 ack 的帧号(待确认帧号)
query 命令用于查询 ack
fec_seq 长度为 16bit 用于 FEC

una+mack 的方式被用于选择重传和快速重传

FEC 说明：
采用异或方式实现 FEC
针对 full frame 即帧长度为 MTU 的帧，进行 FEC 纠错
data frame 的最后两个字节用作 FEC 的 seq.

##### 构建过程
[项目构建过程](https://blog.csdn.net/qq_33271192/article/details/114012316)

##### 使用说明

1. Windows 平台
2. CC3200 平台

##### 性能测试

1. 传输速度
2. 连接时间
3. 执行速度
4. 吞吐量