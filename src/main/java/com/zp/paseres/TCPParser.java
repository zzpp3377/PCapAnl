package com.zp.paseres;


import org.apache.log4j.Logger;

import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;

/**
 * Created by zp on 2017/5/18.
 */
public class TCPParser implements Parser {
    private byte[] pack;
    private int offset;
    private int src_port=0;
    private int des_port=0;
    private long sequence_num=0;
    private long ack_num=0;
    private int data_offset=0;
    private int reserved=0;
    private boolean URG=false;
    private boolean ACK=false;
    private boolean PSH=false;
    private boolean RST=false;
    private boolean SYN=false;
    private boolean FIN=false;
    private int window=0;
    private int check_sum=0;
    private int urgent_pointer=0;
    Logger log=Logger.getLogger(TCPParser.class);
    public TCPParser(byte[]pack,int offset){
        this.pack=pack;
        this.offset=offset;
    }
    public void parse() {
        if(pack.length<offset+20){
            System.out.print("[TCP Header]:\n");
            log.error("Uncomplete Package!!!");
            return;
        }
//        log.info(pack.length+","+offset);
        src_port=(((pack[offset]+256)%256)<<8)+(pack[offset+1]+256)%256;
        offset+=2;
        des_port=(((pack[offset]+256)%256)<<8)+(pack[offset+1]+256)%256;
        offset+=2;
        for(int i=0;i<4;i++){
            sequence_num=sequence_num<<8;
            sequence_num+=(pack[offset+i]+256)%256;
        }
        offset+=4;
        for(int i=0;i<4;i++){
            ack_num=ack_num<<8;
            ack_num+=(pack[offset+i]+256)%256;
        }
        offset+=4;
        data_offset=(pack[offset]>>>4)*4;
//        if(pack.length<offset-12+data_offset){
//            System.out.print("[TCP Header]:\n");
//            log.error("Uncomplete Package!!!");
//            return;
//        }
        log.info(pack.length+","+offset+","+data_offset);
        reserved=((pack[offset]&0x0f)<<2)+(pack[offset+1]>>>6);
        offset++;
        URG=(pack[offset]&0x20)>0;
        ACK=(pack[offset]&0x10)>0;
        PSH=(pack[offset]&0x08)>0;
        RST=(pack[offset]&0x04)>0;
        SYN=(pack[offset]&0x02)>0;
        FIN=(pack[offset]&0x01)>0;
        offset++;
        window=(((pack[offset]+256)%256)<<8)+(pack[offset+1]+256)%256;
        offset+=2;
        check_sum=(((pack[offset]+256)%256)<<8)+(pack[offset+1]+256)%256;
        offset+=2;
        urgent_pointer=(((pack[offset]+256)%256)<<8)+(pack[offset+1]+256)%256;
        offset+=2;
        //暂时不处理头部可选项

        offset+=data_offset-20;
//        log.info(pack.length+","+offset);
        printHead();
    }
    private void printHead(){
        System.out.print("[TCP Header]:\n");
        System.out.print("\tSource port: "+src_port+"\n"); ////////////////////////////待补充
        System.out.print("\tDestination port: "+des_port+"\n"); ////////////////////////////待补充
        System.out.print("\tSequence Number: "+sequence_num+"\n");
        System.out.print("\tAcknowledgment Number: "+ack_num+"\n");
        System.out.print("\tData Offset: "+data_offset+"\n");
        System.out.print("\tReserved: "+reserved+"\n");
        System.out.print("\tURG: "+URG+"\n");
        System.out.print("\tACK: "+ACK+"\n");
        System.out.print("\tPSH: "+PSH+"\n");
        System.out.print("\tRST: "+RST+"\n");
        System.out.print("\tSYN: "+SYN+"\n");
        System.out.print("\tFIN: "+FIN+"\n");
        System.out.print("\tWindow: "+window+"\n");
        System.out.print("\tChecksum: "+check_sum+"\n");
        System.out.print("\tUrgent Pointer: "+urgent_pointer+"\n");

        System.out.print("\tpackage content: ");
        for(int i=offset;i<pack.length;i++){
            System.out.print(Integer.toHexString(pack[i]));
        }
        System.out.print("\n");
    }
}
