package com.zp.paseres;

import org.apache.log4j.Logger;

/**
 * Created by zp on 2017/5/19.
 */
public class DHCPParser implements Parser {
    private byte[] pack;
    private int offset;
    private int operation=0;
    private int type_hardware=0;
    private int len_hardware_addr=0;
    private int hops=0;
    private long id_transaction=0;
    private int seconds=0;
    private int flags=0;
    private int[] ip_addr_client;
    private int[] ip_addr_your;
    private int[] ip_addr_serv;
    private int[] ip_addr_gateway;
    private int[] addr_hardware_client;
    private byte[] name_serv;
    private byte[] name_bootfile;
    Logger log =Logger.getLogger(DHCPParser.class);
    public DHCPParser(byte[] pack,int offset){
        this.pack=pack;
        this.offset=offset;
        ip_addr_client=new int[4];
        ip_addr_your=new int[4];
        ip_addr_serv=new int[4];
        ip_addr_gateway=new int[4];
        addr_hardware_client=new int[6];
        name_serv=new byte[64];
        name_bootfile=new byte[128];
    }
    public void parse() {
        if(pack.length<226+offset){
            System.out.print("[DHCP Header]: \n");
            log.error("Uncomplete Package!!!");
            return;
        }
        operation=(pack[offset]+256)%256;
        offset++;
        type_hardware=(pack[offset]+256)%256;
        if(type_hardware!=1){
            System.out.print("[DHCP Header]: \n");
            log.error("Sorry we just support ethernet on hardware!!!");
            return;
        }
        offset++;
        len_hardware_addr=(pack[offset]+256)%256;
        offset++;
        hops=(pack[offset]+256)%256;
        offset++;
        for(int i=0;i<4;i++){
            id_transaction=id_transaction<<8;
            id_transaction+=(pack[offset+i]+256)%256;
        }
        offset+=4;
        seconds=(((pack[offset]+256)%256)<<8)+(pack[offset+1]+256)%256;
        offset+=2;
        flags=(((pack[offset]+256)%256)<<8)+(pack[offset+1]+256)%256;
        offset+=2;
        for(int i=0;i<4;i++){
            ip_addr_client[i]=(pack[offset+i]+256)%256;
        }
        offset+=4;
        for(int i=0;i<4;i++){
            ip_addr_your[i]=(pack[offset+i]+256)%256;
        }
        offset+=4;
        for(int i=0;i<4;i++){
            ip_addr_serv[i]=(pack[offset+i]+256)%256;
        }
        offset+=4;
        for(int i=0;i<4;i++){
            ip_addr_gateway[i]=(pack[offset+i]+256)%256;
        }
        offset+=4;
        for(int i=0;i<6;i++){
            addr_hardware_client[i]=(pack[offset+i]+256)%256;
        }
        offset+=6;
        for(int i=0;i<64;i++){
            name_serv[i]=pack[offset+i];
        }
        for(int i=0;i<128;i++){
            name_bootfile[i]=pack[offset+i];
        }
        printHead();
    }
    private void printHead(){
        System.out.print("[DHCP Header]: \n");
        System.out.print("\tOperation: "+operation);
        if(operation==1){
            System.out.print(" (request)\n");
        }else{
            System.out.print(" (response)\n");
        }
        System.out.print("\tHardware Type: "+type_hardware+" (ethernet)\n");
        System.out.print("\tHardware Length: "+len_hardware_addr+"\n");
        System.out.print("\tHops: "+hops+"\n");
        System.out.print("\tTransaction ID: "+id_transaction+"\n");
        System.out.print("\tSeconds: "+seconds+"\n");
        System.out.print("\tFlags: 0x"+Integer.toHexString(flags)+"\n");
        System.out.print("\tClient IP Address: ");
        for(int i=0;i<ip_addr_client.length;i++) {
            System.out.print(ip_addr_client[i]);
            if(i<ip_addr_client.length-1){
                System.out.print(".");
            }else{
                System.out.print("\n");
            }
        }
        System.out.print("\tYour IP Address: ");
        for(int i=0;i<ip_addr_your.length;i++) {
            System.out.print(ip_addr_your[i]);
            if(i<ip_addr_your.length-1){
                System.out.print(".");
            }else{
                System.out.print("\n");
            }
        }
        System.out.print("\tServer IP Address: ");
        for(int i=0;i<ip_addr_serv.length;i++) {
            System.out.print(ip_addr_serv[i]);
            if(i<ip_addr_serv.length-1){
                System.out.print(".");
            }else{
                System.out.print("\n");
            }
        }
        System.out.print("\tGateway IP Address: ");
        for(int i=0;i<ip_addr_gateway.length;i++) {
            System.out.print(ip_addr_gateway[i]);
            if(i<ip_addr_gateway.length-1){
                System.out.print(".");
            }else{
                System.out.print("\n");
            }
        }
        System.out.print("\tClient Hardware Address: ");
        for(int i=0;i<6;i++){
            System.out.print(Integer.toHexString(addr_hardware_client[i]));
            if(i<addr_hardware_client.length-1){
                System.out.print(":");
            }else{
                System.out.print("\n");
            }
        }
        String tmp=new String(name_serv);
        System.out.print("\tServer Name: "+tmp+"\n");
        tmp=new String(name_bootfile);
        System.out.print("\tBootfile Name: "+tmp+"\n");

        System.out.print("\tpackage content: ");
        for(int i=offset;i<pack.length;i++){
            System.out.print(Integer.toHexString(pack[i]));
        }
        System.out.print("\n");
    }
}
