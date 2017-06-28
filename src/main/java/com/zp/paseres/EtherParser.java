package com.zp.paseres;


import com.zp.Capturer;
import org.apache.log4j.Logger;

/**
 * Created by zp on 2017/5/17.
 */
public class EtherParser implements Parser{
    private  byte [] pack;
    private  int offset;
    private  int[] des_add;
    private  int[] src_add;
    private  int type;
    private static Logger log= Logger.getLogger(EtherParser.class);
    private static final int LEN_ETHER_HEAD=14;
    public EtherParser(byte [] pack,int offset){
        this.pack=pack;
        this.offset=offset;
        des_add=new int[6];
        src_add=new int[6];
        type=0;
    }

    public void parse() {
        if(pack.length<LEN_ETHER_HEAD){
            System.out.println("[Ether Header]:");
            log.error("unknown pack!!!");
            return;
        }
        for(int i=0;i<des_add.length;i++){
            des_add[i]=(pack[i+offset]+256)%256;
        }
        offset=offset+des_add.length;
        for(int i=0;i<src_add.length;i++){
            src_add[i]=(pack[i+offset]+256)%256;
        }
        offset=offset+src_add.length;
        for(int i=0;i<2;i++) {
            type=type<<8;
            type += (pack[offset+i] + 256)%256;
        }
        offset=offset+2;
        printHead();
    }
    private void printHead(){
        System.out.println("[Ether Header]:");
        System.out.print("\tDestination Address: ");
        for(int i=0;i<des_add.length;i++){
            System.out.print(des_add[i]);
            if(i<5){
                System.out.print(":");
            }else{
                System.out.print("\n");
            }
        }
        System.out.print("\tSource Address: ");
        for(int i=0;i<src_add.length;i++){
            System.out.print(src_add[i]);
            if(i<5){
                System.out.print(":");
            }else{
                System.out.print("\n");
            }
        }
        System.out.print("\tType: ");
        String tp=null;
        switch (type){
            case 0x0800: {
                tp=" (IP)";
                System.out.print("0x"+Integer.toHexString(type)+tp+"\n");
                IpParser ip_parser=new IpParser(pack,offset);
                ip_parser.parse();
                break;
            }
            case 0x0806: {
                tp=" (ARP)";
                System.out.print("0x"+Integer.toHexString(type)+tp+"\n"+"[ARP Header]:\n");
                ArpParser arp_parser=new ArpParser(pack,offset);
                arp_parser.parse();
                break;
            }
            case 0x8035: {
                tp=" (RARP)";
                System.out.print("0x"+Integer.toHexString(type)+tp+"\n"+"[RARP Header]:\n");
                ArpParser rarp_parser=new ArpParser(pack,offset);
                rarp_parser.parse();
                break;
            }
            default:tp=null;
        }
        if(tp==null){
            log.error("\"unknown pack!!!\"");
            return;
        }

    }
}
