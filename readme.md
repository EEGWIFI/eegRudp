### eegRudp
eegRudp��һ����ƽ̨����Ƭ��/Linux/Windows���Ļ��� udp + arq + fec �Ŀ��ٿɿ�Э��
##### ԭ�����
rto(Retransmission Timeout) ���㣺
��ʼ��
rtts = rttm;
rttd = rttm / 2;

������
rtts = (1 - alpha) * rtts + alpha * rttm; // alpha = 1 / 8
rttd = (1 - beta ) * rttd + beta  * abs(rttm - rtts); // beta = 1 / 4

������
rto  = rtts + r * rttd;

��ʱ��
rto  = 1.5 * rto;


֡���壺
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

data_full  frame Ϊ���� fec �� data ��֡
data_short frame Ϊ���� fec �� data ��֡
data_fecN Ϊÿ N ֡��һ�� fec ֡��N >= 2 && N <= 32��


Э���ص㣺
ѡ���ش��������ش������ӳ� ACK��UNA + MACK�����������ء�FEC ǰ�����


Э��˵����
seq una ����Ϊ 24bit��recv_win_size Ϊ 16bit
ack ֡������ una, mack �� rwnd size ��Ϣ
mack 24bit ��һ�� bitmap, ������ una ֮�󣬵����Ѿ��� ack ��֡��(��ȷ��֡��)
query �������ڲ�ѯ ack
fec_seq ����Ϊ 16bit ���� FEC

una+mack �ķ�ʽ������ѡ���ش��Ϳ����ش�

FEC ˵����
�������ʽʵ�� FEC
��� full frame ��֡����Ϊ MTU ��֡������ FEC ����
data frame ����������ֽ����� FEC �� seq.

##### ��������
[��Ŀ��������](https://blog.csdn.net/qq_33271192/article/details/114012316)

##### ʹ��˵��

1. Windows ƽ̨
2. CC3200 ƽ̨

##### ���ܲ���

1. �����ٶ�
2. ����ʱ��
3. ִ���ٶ�
4. ������