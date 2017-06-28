package com.zp.paseres;

import org.apache.log4j.Logger;

/**
 * Created by zp on 2017/5/18.
 */
public class UDPParse implements Parser {
    private byte[] pack;
    private int offset;
    private int src_port=0;
    private int des_port=0;
    private int len_total=0;
    private int check_sum=0;
    Logger log=Logger.getLogger(UDPParse.class);
    public  UDPParse(byte[]pack, int offset){
        this.pack=pack;
        this.offset=offset;
    }
    public void parse() {
        if(pack.length<offset+8){
            System.out.print("[UDP Header]: \n");
            log.error("Uncomplete Package!!!");
            return;
        }
        src_port=(((pack[offset]+256)%256)<<8)+(pack[offset+1]+256)%256;
        offset+=2;
        des_port=(((pack[offset]+256)%256)<<8)+(pack[offset+1]+256)%256;
        offset+=2;
        len_total=(((pack[offset]+256)%256)<<8)+(pack[offset+1]+256)%256;
        offset+=2;
        check_sum=(((pack[offset]+256)%256)<<8)+(pack[offset+1]+256)%256;
        offset+=2;
        printHead();
    }
    private void printHead(){
        System.out.print("[UDP Header]: \n");
        System.out.print("\tSource port: "+src_port+"\n");
        System.out.print("\tDestination port: "+des_port+"\n");
        System.out.print("\tLength: "+len_total+" bytes\n");
        System.out.print("\tChecksum: 0x"+Integer.toHexString(check_sum)+"\n");
        if((src_port==67&&des_port==68)||(src_port==68&&des_port==67)){                    //DHCP协议
            DHCPParser dhcp_parser=new DHCPParser(pack,offset);
            dhcp_parser.parse();
        }else {
            System.out.print("\tpackage content: ");
            for (int i = offset; i < pack.length; i++) {
                System.out.print(Integer.toHexString(pack[i]));
            }
            System.out.print("\n");
        }
    }
}
