package com.zp;

import com.zp.paseres.EtherParser;
import org.apache.log4j.Logger;
import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.NifSelector;

import java.io.IOException;
import java.util.List;

/**
 * Created by zp on 2017/5/16.
 */
public class Capturer {
    private final int DEV=0;
    private static Logger log= Logger.getLogger(Capturer.class);
    // 获取所有网卡设备
    List<PcapNetworkInterface> alldev = null;
    // 根据设备名称初始化抓包接口
    PcapNetworkInterface nif=null;
    // 抓取包长度
    int snaplen = 64 * 1024;
    // 超时50ms
    int timeout = 50;
    /** 设置过滤规则 **/
    String filter = "";
    //抓包器句柄
    PcapHandle handle=null;

    public Capturer() {

        try {
            nif=new NifSelector().selectNetworkInterface();
        } catch (IOException e1) {
            e1.printStackTrace();
        }
        if(nif==null){
            return;
        }
        log.info(nif.getName()+nif.getDescription());
        try {
            if(Setting.getInstance().getPromiscuous().equals("no")) {
                handle = nif.openLive(snaplen, PcapNetworkInterface.PromiscuousMode.NONPROMISCUOUS, timeout);
            }else if(Setting.getInstance().getPromiscuous().equals("yes")){
                handle = nif.openLive(snaplen, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, timeout);
            }else{
                log.error("please chaeck the setting.properties for promiscuous,it can only be \"yes\" or \"no\"");
            }
        } catch (PcapNativeException e) {
            e.printStackTrace();
        }
            // 设置过滤器
        try {
            handle.setFilter(Setting.getInstance().getFilter(), BpfProgram.BpfCompileMode.OPTIMIZE);
        } catch (PcapNativeException e) {
            e.printStackTrace();
        } catch (NotOpenException e) {
            e.printStackTrace();
        }
    }

    public void capture( ){
        PacketListener listener
                = new PacketListener() {
            public void gotPacket(Packet packet) {
                System.out.print("\n");
                System.out.println(handle.getTimestamp());
//                System.out.println(packet);    ///pcap4j的包解析
                byte[] p=packet.getRawData();
//                for(int i=0;i<p.length;i++){
//                    System.out.print(p[i]+",");
//                }
//                System.out.print("\n");
                EtherParser ether_parse=new EtherParser(p,0);
                ether_parse.parse();
            }
        };
        try {
            int count=Integer.parseInt(Setting.getInstance().getCount());
            handle.loop( count, listener );
        } catch (InterruptedException e) {
            e.printStackTrace();
        } catch (PcapNativeException e) {
            e.printStackTrace();
        } catch (NotOpenException e) {
            e.printStackTrace();
        }
    }
}
