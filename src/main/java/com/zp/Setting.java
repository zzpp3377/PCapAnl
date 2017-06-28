package com.zp;

import org.apache.log4j.Logger;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Properties;


/**
 * Created by zp on 2017/5/25.
 */
public class Setting {
    private String filter;
    private String promiscuous;
    private String count;
    private static final String ACTIONPATH = "."+ File.separator+"config"+File.separator+ "setting.properties";
    private static Setting instance=null;
    Logger log= Logger.getLogger(Setting.class);
    private Setting(){}

    public static Setting getInstance(){
        if(instance==null){
            instance= new Setting().getNewDbConfig();
        }
        return instance;
    }

    private Setting getNewDbConfig(){
        Setting set=new Setting();
        Properties prop = new Properties();
        FileInputStream fis=null;
        try{
            fis = new FileInputStream(new File(ACTIONPATH));
            prop.load(fis);
            set.filter =prop.getProperty("filter");
            set.promiscuous=prop.getProperty("promiscuous");
            set.count=prop.getProperty("count");
        }catch(FileNotFoundException e){
            e.printStackTrace();
        }catch(IOException e){
            e.printStackTrace();
        }
        log.info(set.filter);
        return set;
    }

    public String getFilter() {
        return filter;
    }

    public String getPromiscuous() {
        return promiscuous;
    }

    public String getCount() {
        return count;
    }
}

