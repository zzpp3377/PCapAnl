package com.zp.paseres;

import org.apache.log4j.Logger;

/**
 * Created by zp on 2017/5/17.
 */
public class ArpParser implements Parser {
    private byte[] pack;
    private int offset;
    private int type_hardware=0;
    private int type_protocol=0;
    private int len_hard_addr=0;
    private int len_prtcl_addr=0;
    private int operation=0;
    private int[] src_hard_addr;
    private int[] src_prtcl_addr;
    private int[] des_hard_addr;
    private int[] des_prtcl_addr;
    private static Logger log= Logger.getLogger(ArpParser.class);
    private static final int LEN_ARP=28;
    public ArpParser(byte[] pack,int offset){
        this.pack=pack;
        this.offset=offset;
        src_hard_addr=new int[6];
        src_prtcl_addr=new int[4];
        des_hard_addr=new int[6];
        des_prtcl_addr=new int[4];
    }
    public void parse() {
        if(pack.length<offset+LEN_ARP){
//            System.out.println("[ARP Header]:");
            log.error("uncomplete pack!!!");
        }
        for(int i=0;i<2;i++){
            type_hardware=type_hardware<<8;
            type_hardware +=(pack[i+offset]+256)%256;
        }
        offset+=2;
        for(int i=0;i<2;i++){
            type_protocol=type_protocol<<8;
            type_protocol +=(pack[i+offset]+256)%256;
        }
        offset+=2;
        len_hard_addr=(pack[offset]+256)%256;
        offset++;
        len_prtcl_addr=(pack[offset]+256)%256;
        offset++;
        for(int i=0;i<2;i++){
            operation=operation<<8;
            operation +=(pack[i+offset]+256)%256;
        }
        offset+=2;
        for(int i=0;i<6;i++){
            src_hard_addr[i]=(pack[i+offset]+256)%256;
        }
        offset+=6;
        for(int i=0;i<4;i++){
            src_prtcl_addr[i]=(pack[i+offset]+256)%256;
        }
        offset+=4;
        for(int i=0;i<6;i++){
            des_hard_addr[i]=(pack[i+offset]+256)%256;
        }
        offset+=6;
        for(int i=0;i<4;i++){
            des_prtcl_addr[i]=(pack[i+offset]+256)%256;
        }
        offset+=4;
        printHead();
    }

    private void printHead(){
//        System.out.println("[ARP Header]:");
        System.out.print("\tHardware type: ");
        if(type_hardware==1){
            System.out.print(type_hardware+" (Ethernet)\n");
        }else{
            System.out.print(type_hardware+"\n");
            log.error("unknown package!!!");
            return;
        }
        System.out.print("\tProtocol type: ");
        if(type_protocol==0x0800){
            System.out.print("0x"+Integer.toHexString(type_protocol)+" (IP)\n");
        }else{
            System.out.print(type_protocol+"\n");
            log.error("unknown package!!!");
            return;
        }
        System.out.print("\tHardware address length: "+len_hard_addr+" bytes\n");
        System.out.print("\tProtocol address length: "+len_prtcl_addr+" bytes\n");
        System.out.print("\tOperation: ");
        String op=null;
        switch (operation){
            case 1:op=" (request)";break;
            case 2:op=" (response)";break;
            case 3:op=" (request)";break;
            case 4:op=" (response)";break;
        }
        System.out.print(operation+op+"\n");
        System.out.print("\tSource hardware address: ");
        for(int i=0;i<src_hard_addr.length;i++){
            System.out.print(src_hard_addr[i]);
            if(i<src_hard_addr.length-1){
                System.out.print(":");
            }else{
                System.out.print("\n");
            }
        }
        System.out.print("\tSource protocol address: ");
        for(int i=0;i<src_prtcl_addr.length;i++){
            System.out.print(src_prtcl_addr[i]);
            if(i<src_prtcl_addr.length-1){
                System.out.print(":");
            }else{
                System.out.print("\n");
            }
        }
        System.out.print("\tDestination hardware address: ");
        for(int i=0;i<des_hard_addr.length;i++){
            System.out.print(des_hard_addr[i]);
            if(i<des_hard_addr.length-1){
                System.out.print(":");
            }else{
                System.out.print("\n");
            }
        }
        System.out.print("\tDestination protocol address: ");
        for(int i=0;i<des_prtcl_addr.length;i++){
            System.out.print(des_prtcl_addr[i]);
            if(i<des_prtcl_addr.length-1){
                System.out.print(":");
            }else{
                System.out.print("\n");
            }
        }

    }
}
