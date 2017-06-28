package com.zp.paseres;

import org.apache.log4j.Logger;

/**
 * Created by zp on 2017/5/18.
 */
public class ICMPParser implements Parser {
    private byte[] pack;
    private int offset;
    private int type=0;
    private int code=0;
    private int check_sum=0;
    private int identification=0;
    private int sequence_num=0;
    Logger log=Logger.getLogger(ICMPParser.class);

    public ICMPParser(byte[]pack,int offset){
        this.pack=pack;
        this.offset=offset;
    }
    public void parse() {
        if(pack.length<offset+4){
            System.out.print("[ICMPv4 Common Header]:\n");
            log.error("Uncomplete Package!!!");
            return;
        }
        type=(pack[offset]+256)%256;
        offset++;
        code=(pack[offset]+256)%256;
        offset++;
        check_sum=(((pack[offset]+256)%256)<<8)+(pack[offset+1]+256)%256;
        offset+=2;
        switch (type){
            case 0:
            case 8:{
                identification=(((pack[offset]+256)%256)<<8)+(pack[offset+1]+256)%256;
                offset+=2;
                sequence_num=(((pack[offset]+256)%256)<<8)+(pack[offset+1]+256)%256;
                offset+=2;
                break;
            }
            default:
        }
        printHead();
    }
    private void printHead(){
        System.out.print("[ICMPv4 Common Header]:\n");
        System.out.print("\tType: "+type+"\n");
        System.out.print("\tCode: "+code+"\n");
        System.out.print("\tChecksum: 0x"+Integer.toHexString(check_sum)+"\n");
        switch (type){
            case 0:{
                System.out.print("[ICMPv4 Echo Reply Header]:\n");
                System.out.print("\tIdentifier: "+identification+"\n");
                System.out.print("\tSequenceNumber: "+sequence_num+"\n");
                break;
            }
            case 8:{
                System.out.print("[ICMPv4 Echo Header]:\n");
                System.out.print("\tIdentifier: "+identification+"\n");
                System.out.print("\tSequenceNumber: "+sequence_num+"\n");
                break;
            }
            default:{
                log.error("sorry,we just support ICMP Echo Protocl (ping)!!!");
            }
        }
        System.out.print("\tpackage content: ");
        for(int i=offset;i<pack.length;i++){
            System.out.print(Integer.toHexString(pack[i]));
        }
        System.out.print("\n");
    }
}
