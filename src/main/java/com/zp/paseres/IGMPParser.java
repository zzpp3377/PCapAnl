package com.zp.paseres;


import org.apache.log4j.Logger;

import java.util.LinkedList;
import java.util.List;

/**
 * Created by zp on 2017/5/18.
 */
public class IGMPParser implements  Parser{
    private byte [] pack;
    private int offset;
    private boolean v3=false;
    private int type=0;
    private int max_resp_code=0;
    private int check_sum=0;
    private int[] group_addr;
    private int reserved=0;
    private boolean s=false;
    private  int qrv=0;
    private int qqic=0;
    private int src_num=0;
    List<int[]> list_src;

    Logger log =Logger.getLogger(IGMPParser.class);
    public  IGMPParser(byte[] pack,int offset){
        this.pack=pack;
        this.offset=offset;
        group_addr=new int[4];
        list_src=new LinkedList<int[]>();
    }
    public void parse() {
        if(pack.length<offset+8){
            System.out.print("[IGMP Header]:\n");
            log.error("Uncomplete Package!!!");
            return;
        }
        if(pack.length-14-offset>=12){
            v3=true;
        }
        type=(pack[offset]+256)%256;
        offset++;
        max_resp_code=(pack[offset]+256)%256;
        offset++;
        check_sum=(((pack[offset]+256)%256)<<8)+(pack[offset+1]+256)%256;
        offset+=2;
        switch (type){
            case 0x12:
            case 0x16:
            case 0x17:{
                    for(int i=0;i<4;i++){
                        group_addr[i]=(pack[offset+i]+256)%256;
                    }
                    offset+=4;
                    break;
                }
            case 0x11:{
                    for(int i=0;i<4;i++){
                        group_addr[i]=(pack[offset+i]+256)%256;
                    }
                    offset+=4;
                    if(v3==true){
                        reserved=(pack[offset]>>4);
                        s=(pack[offset]&0x08)>0;
                        qrv=pack[offset]&0x07;
                        offset++;
                        qqic=(pack[offset]+256)%256;
                        offset++;
                        src_num=(((pack[offset]+256)%256)<<8)+(pack[offset+1]+256)%256;
                        offset+=2;
                        //并没有那些源地址对地址进行解析
                    }
            }
            case 0x22:{
                reserved=(((pack[offset]+256)%256)<<8)+(pack[offset+1]+256)%256;
                offset+=2;
                src_num=(((pack[offset]+256)%256)<<8)+(pack[offset+1]+256)%256;
                offset+=2;
                //并没有对那些源地址进行解析
            }

        }
        printHead();
    }
    private void printHead(){
        System.out.print("[IGMP Header]:\n");
        System.out.print("\tType: 0x"+Integer.toHexString(type));
        if(v3==true||type==0x22){
            System.out.print(" (V3)\n");
        }else{
            System.out.print(" (V2)\n");
        }
        switch (type){
            case 0x12:
            case 0x16:
            case 0x17:{
                System.out.print("\tReserved: "+max_resp_code+"\n");
                System.out.print("\tCheck Sum: 0x"+Integer.toHexString(check_sum)+"\n");
                System.out.print("\tGroup Address: ");
                for(int i=0;i<group_addr.length;i++){
                    System.out.print(group_addr[i]);
                    if(i<group_addr.length-1){
                        System.out.print(":");
                    }else{
                        System.out.print("\n");
                    }
                }
                break;
            }
            case 0x11:{
                if(max_resp_code>128){                                                          //代表V3且max_resp_code>128
                    System.out.print("\tMax_Resp_Code: "+(((max_resp_code&0x0f)|0x10)<<(((max_resp_code&0x70)>>4)+3))*0.1+" s\n");
                }else{
                    System.out.print("\tMax_Resp_Code: "+max_resp_code*0.1+" s\n");
                }
                System.out.print("\tCheck Sum: 0x"+Integer.toHexString(check_sum)+"\n");
                System.out.print("\tGroup Address: ");
                for(int i=0;i<group_addr.length;i++){
                    System.out.print(group_addr[i]);
                    if(i<group_addr.length-1){
                        System.out.print(":");
                    }else{
                        System.out.print("\n");
                    }
                }
                if(v3==true){
                    System.out.print("\tReserved: "+reserved+"\n");
                    System.out.print("\tS: "+s+"\n");
                    System.out.print("\tQRV: "+qrv+"\n");
                    System.out.print("\tQQIC: ");
                    if(qqic>128){
                        System.out.print((((qqic&0x0f)|0x10)<<(((qqic&0x70)>>4)+3))+" s\n");
                    }else{
                        System.out.print(qqic+" s\n");
                    }
                    System.out.print("Number of Sources: "+src_num+"\n");
                }
                break;
            }
            case 0x22:{
                System.out.print("\tReserved: "+max_resp_code+"\n");
                System.out.print("\tCheck Sum: 0x"+Integer.toHexString(check_sum)+"\n");
                System.out.print("\tReserved: "+reserved+"\n");
                System.out.print("\tNumber of Group Record: "+src_num+"\n");
                break;
            }
        }
        System.out.print("\tpackage content: ");
        for(int i=offset;i<pack.length;i++){
            System.out.print(Integer.toHexString(pack[i]));
        }
        System.out.print("\n");
    }
}
