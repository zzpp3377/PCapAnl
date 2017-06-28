package com.zp.paseres;

import org.apache.log4j.Logger;

/**
 * Created by zp on 2017/5/17.
 */
public class IpParser implements Parser {
    private byte []pack;
    private int offset;
    private int version=0;
    private int len_head=0;
    private int diff_serv=0;
    private int len_total=0;
    private int identification=0;
    private int flags=0;
    private int fragment_offset=0;
    private int ttl=0;
    private int protocol=0;
    private int checksum=0;
    private int[] src_addr;
    private int[] des_addr;
    Logger log=Logger.getLogger(IpParser.class);
    public IpParser(byte[]pack,int offset){
        this.pack=pack;
        this.offset=offset;
        src_addr=new int[4];
        des_addr=new int[4];
    }
    public void parse() {
        if(pack.length<offset+20){
            System.out.print("[IP Header]:");
            log.error("uncomplete package!!!");
            return;
        }
        version=pack[offset]>>>4;
        len_head=(pack[offset]&0x0f)*4;
        if(pack.length<offset+len_head){
            System.out.print("[IP Header]:");
            log.error("uncomplete package!!!");
            return;
        }
        offset++;
        diff_serv=(pack[offset]+256)%256;
        offset++;
        len_total=(((pack[offset]+256)%256)<<8)+(pack[offset+1]+256)%256;
        offset+=2;
        identification=(((pack[offset]+256)%256)<<8)+(pack[offset+1]+256)%256;
        offset+=2;
        flags=pack[offset]>>>5;
        fragment_offset=((pack[offset]&0x1f)<<8)+(pack[offset+1]+256)%256;
        offset+=2;
        ttl=(pack[offset]+256)%256;
        offset++;
        protocol=(pack[offset]+256)%256;
        offset++;
        checksum=(((pack[offset]+256)%256)<<8)+(pack[offset+1]+256)%256;
        offset+=2;
        for(int i=0;i< src_addr.length;i++){
            src_addr[i]=(pack[i+offset]+256)%256;
        }
        offset+=4;
        for(int i=0;i<des_addr.length;i++){
            des_addr[i]=(pack[i+offset]+256)%256;
        }
        offset+=4;
        //暂时不进行IP头可选字段的解析
        offset+=len_head-20;
        printHead();
    }
    public void printHead(){
        System.out.print("[IP Header]:\n");
        System.out.print("\tVersion: ");
        if (version==4){
            System.out.print(version+" (IPv4)\n");
        }else{
            System.out.print("\n");
            log.error("unknown package!!!");
            return;
        }
        System.out.print("\tHead Length: "+len_head+" bytes"+"\n");
        System.out.print("\tDiffSev: "+Integer.toBinaryString(diff_serv)+"\n");
        System.out.print("\tTotal Length: "+len_total+" bytes"+"\n");
        System.out.print("\tIdentification: "+identification+"\n");
        System.out.print("\tFlags: (reserved, Don't Fragment, More Fragment)=");
        if((flags&0x04)>0){
            System.out.print("1,");
        }else{
            System.out.print("0,");
        }
        if((flags&0x02)>0){
            System.out.print("1,");
        }else{
            System.out.print("0,");
        }if((flags&0x01)>0){
            System.out.print("1\n");
        }else{
            System.out.print("0\n");
        }
        System.out.print("\tFragment offset: "+fragment_offset+" bytes\n");
        System.out.print("\tTTL: "+ttl+"\n");
        System.out.print("\tProtocol: "+protocol);
        switch (protocol){
            case 1:System.out.print(" (ICMP)\n");break;
            case 2:System.out.print(" (IGMP)\n");break;
            case 6:System.out.print(" (TCP)\n");break;
            case 17:System.out.print(" (UDP)\n");break;
            default:System.out.print("unknown\n");
        }
        System.out.print("\tHeader checksum: 0x"+Integer.toHexString(checksum)+"\n");
        System.out.print("\tSource address: ");
        for(int i=0;i<src_addr.length;i++){
            System.out.print(src_addr[i]);
            if(i<src_addr.length-1){
                System.out.print(".");
            }else{
                System.out.print("\n");
            }
        }
        System.out.print("\tDestination address: ");
        for(int i=0;i<des_addr.length;i++){
            System.out.print(des_addr[i]);
            if(i<des_addr.length-1){
                System.out.print(".");
            }else{
                System.out.print("\n");
            }
        }
        switch (protocol){
            case 1:{                                            //ICMP
                ICMPParser icmp_parser=new ICMPParser(pack,offset);
                icmp_parser.parse();
                break;
            }
            case 2:{                                           //IGMP
                IGMPParser igmp_parser=new IGMPParser(pack,offset);
                igmp_parser.parse();
                break;
            }
            case 6:{                                           //TCP
                TCPParser tcp_parser=new TCPParser(pack,offset);
                tcp_parser.parse();
                break;
            }
            case 17:{                                          //UDP
                UDPParse udp_parser=new UDPParse(pack,offset);
                udp_parser.parse();
                break;
            }
            default:System.out.print("unknown package!!!\n");return;
        }
    }
}
